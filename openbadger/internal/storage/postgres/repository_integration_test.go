package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mbaybarsk/openbadger/internal/auth"
	"github.com/mbaybarsk/openbadger/internal/correlation"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

func TestRepositoryCreateRecordsIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openIntegrationPool(t, ctx)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := NewRepository(tx)
	slug := fmt.Sprintf("site-%s", uuid.NewString())

	site, err := repo.CreateSite(ctx, CreateSiteParams{
		Slug:        slug,
		Name:        "Istanbul HQ",
		Description: "Primary site",
	})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	node, err := repo.CreateNode(ctx, CreateNodeParams{
		SiteID:        site.ID,
		Kind:          NodeKindCollector,
		Name:          "collector-01",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh", "snmp", "ssh"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	storedNode, err := repo.GetNodeByAuthTokenHash(ctx, auth.HashToken("node-token"))
	if err != nil {
		t.Fatalf("GetNodeByAuthTokenHash returned error: %v", err)
	}

	if storedNode.ID != node.ID {
		t.Fatalf("storedNode.ID = %q, want %q", storedNode.ID, node.ID)
	}

	heartbeatAt := time.Now().UTC().Truncate(time.Second)
	updatedNode, err := repo.UpdateNodeHeartbeat(ctx, nodes.HeartbeatParams{
		NodeID:          node.ID,
		Name:            "collector-01-renamed",
		Version:         "0.1.1",
		Capabilities:    []string{"icmp", "ssh"},
		HealthStatus:    "healthy",
		LastHeartbeatAt: heartbeatAt,
	})
	if err != nil {
		t.Fatalf("UpdateNodeHeartbeat returned error: %v", err)
	}

	if updatedNode.Name != "collector-01-renamed" {
		t.Fatalf("updatedNode.Name = %q, want %q", updatedNode.Name, "collector-01-renamed")
	}

	if updatedNode.LastHeartbeatAt == nil || !updatedNode.LastHeartbeatAt.Equal(heartbeatAt) {
		t.Fatalf("updatedNode.LastHeartbeatAt = %v, want %v", updatedNode.LastHeartbeatAt, heartbeatAt)
	}

	job, err := repo.CreateJob(ctx, CreateJobParams{
		SiteID:     site.ID,
		NodeID:     &node.ID,
		Kind:       "scan",
		Capability: "icmp",
		Status:     jobtypes.StatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	observedAt := time.Now().UTC().Truncate(time.Second)
	payload, err := json.Marshal(map[string]any{
		"schema_version": "0.1",
		"observation_id": uuid.NewString(),
		"type":           "icmp.alive",
		"scope":          "sighting",
		"site_id":        site.ID,
		"job_id":         job.ID,
		"emitter": map[string]any{
			"kind":       "collector",
			"id":         node.ID,
			"name":       node.Name,
			"version":    node.Version,
			"capability": "icmp",
		},
		"observed_at": observedAt.Format(time.RFC3339),
		"facts":       map[string]any{"reachable": true},
		"evidence": map[string]any{
			"confidence":      1.0,
			"source_protocol": "icmp",
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	observation, err := repo.CreateObservation(ctx, CreateObservationParams{
		SiteID:     site.ID,
		JobID:      &job.ID,
		NodeID:     &node.ID,
		Type:       "icmp.alive",
		Scope:      "sighting",
		ObservedAt: observedAt,
		Payload:    payload,
	})
	if err != nil {
		t.Fatalf("CreateObservation returned error: %v", err)
	}

	assertRecordExists(t, ctx, tx, `SELECT slug FROM sites WHERE id = $1`, site.ID, site.Slug)
	assertRecordExists(t, ctx, tx, `SELECT name FROM nodes WHERE id = $1`, node.ID, updatedNode.Name)
	assertRecordExists(t, ctx, tx, `SELECT status FROM jobs WHERE id = $1`, job.ID, string(job.Status))
	assertRecordExists(t, ctx, tx, `SELECT type FROM observations WHERE observation_id = $1`, observation.ID, observation.Type)
}

func TestRepositoryLeaseAndUpdateJobIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openIntegrationPool(t, ctx)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := NewRepository(tx)
	site, node := createSiteAndCollector(t, ctx, repo)

	job, err := repo.CreateJob(ctx, CreateJobParams{
		SiteID:     site.ID,
		Kind:       "scan",
		Capability: "ssh",
		Status:     jobtypes.StatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	leasedAt := time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC)
	leased, err := repo.LeaseJob(ctx, LeaseJobParams{
		SiteID:        site.ID,
		NodeID:        node.ID,
		Capabilities:  []string{"ssh"},
		LeaseDuration: 45 * time.Second,
		Now:           leasedAt,
	})
	if err != nil {
		t.Fatalf("LeaseJob returned error: %v", err)
	}

	if leased.ID != job.ID {
		t.Fatalf("leased.ID = %q, want %q", leased.ID, job.ID)
	}

	if leased.Status != jobtypes.StatusRunning {
		t.Fatalf("leased.Status = %q, want %q", leased.Status, jobtypes.StatusRunning)
	}

	if leased.LeaseOwnerNodeID == nil || *leased.LeaseOwnerNodeID != node.ID {
		t.Fatalf("leased.LeaseOwnerNodeID = %v, want %q", leased.LeaseOwnerNodeID, node.ID)
	}

	if leased.StartedAt == nil || !leased.StartedAt.Equal(leasedAt) {
		t.Fatalf("leased.StartedAt = %v, want %v", leased.StartedAt, leasedAt)
	}

	if leased.LeaseExpiresAt == nil || !leased.LeaseExpiresAt.Equal(leasedAt.Add(45*time.Second)) {
		t.Fatalf("leased.LeaseExpiresAt = %v, want %v", leased.LeaseExpiresAt, leasedAt.Add(45*time.Second))
	}

	completedAt := leasedAt.Add(10 * time.Second)
	updated, err := repo.UpdateJobStatus(ctx, UpdateJobStatusParams{
		JobID:  job.ID,
		NodeID: node.ID,
		Status: jobtypes.StatusSuccess,
		Now:    completedAt,
	})
	if err != nil {
		t.Fatalf("UpdateJobStatus returned error: %v", err)
	}

	if updated.Status != jobtypes.StatusSuccess {
		t.Fatalf("updated.Status = %q, want %q", updated.Status, jobtypes.StatusSuccess)
	}

	if updated.CompletedAt == nil || !updated.CompletedAt.Equal(completedAt) {
		t.Fatalf("updated.CompletedAt = %v, want %v", updated.CompletedAt, completedAt)
	}

	if updated.LeaseOwnerNodeID != nil {
		t.Fatalf("updated.LeaseOwnerNodeID = %v, want nil", updated.LeaseOwnerNodeID)
	}

	if updated.LeaseExpiresAt != nil {
		t.Fatalf("updated.LeaseExpiresAt = %v, want nil", updated.LeaseExpiresAt)
	}
}

func TestRepositoryLeaseJobSingleOwnerIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openIntegrationPool(t, ctx)
	repo := NewRepository(pool)
	site, nodeA, nodeB := createSiteAndTwoCollectors(t, ctx, repo)

	if _, err := repo.CreateJob(ctx, CreateJobParams{
		SiteID:     site.ID,
		Kind:       "scan",
		Capability: "ssh",
		Status:     jobtypes.StatusQueued,
	}); err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	type leaseResult struct {
		job Job
		err error
	}

	results := make(chan leaseResult, 2)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup

	lease := func(nodeID string) {
		defer waitGroup.Done()
		<-start
		job, err := repo.LeaseJob(ctx, LeaseJobParams{
			SiteID:        site.ID,
			NodeID:        nodeID,
			Capabilities:  []string{"ssh"},
			LeaseDuration: 30 * time.Second,
			Now:           time.Date(2026, time.April, 4, 10, 30, 0, 0, time.UTC),
		})
		results <- leaseResult{job: job, err: err}
	}

	waitGroup.Add(2)
	go lease(nodeA.ID)
	go lease(nodeB.ID)
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	unavailable := 0
	for result := range results {
		switch {
		case result.err == nil:
			successes++
		case errors.Is(result.err, jobtypes.ErrLeaseUnavailable):
			unavailable++
		default:
			t.Fatalf("LeaseJob returned unexpected error: %v", result.err)
		}
	}

	if successes != 1 {
		t.Fatalf("successful leases = %d, want %d", successes, 1)
	}

	if unavailable != 1 {
		t.Fatalf("unavailable leases = %d, want %d", unavailable, 1)
	}
}

func TestRepositoryAssetPersistenceIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openIntegrationPool(t, ctx)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := NewRepository(tx)
	site, node := createSiteAndCollector(t, ctx, repo)
	observedAt := time.Date(2026, time.April, 4, 13, 30, 0, 0, time.UTC)

	payload := mustMarshalObservation(t, observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          "ssh.host",
		Scope:         "asset",
		SiteID:        site.ID,
		Emitter: &observations.Emitter{
			Kind: "collector",
			ID:   node.ID,
		},
		ObservedAt: observedAt,
		Identifiers: &observations.Identifiers{
			SerialNumber: "SER-001",
			Hostnames:    []string{"host-1"},
		},
		Addresses: &observations.Addresses{IPAddresses: []string{"192.0.2.10"}},
		Facts:     map[string]any{"hostname": "host-1"},
		Evidence:  &observations.Evidence{Confidence: 0.9, SourceProtocol: "ssh"},
	})

	observation, err := repo.CreateObservation(ctx, CreateObservationParams{
		SiteID:     site.ID,
		NodeID:     &node.ID,
		Type:       "ssh.host",
		Scope:      "asset",
		ObservedAt: observedAt,
		Payload:    payload,
	})
	if err != nil {
		t.Fatalf("CreateObservation returned error: %v", err)
	}

	asset, err := repo.CreateAsset(ctx, correlation.CreateAssetParams{
		SiteID:      site.ID,
		Provisional: false,
		FirstSeen:   observedAt,
		LastSeen:    observedAt,
	})
	if err != nil {
		t.Fatalf("CreateAsset returned error: %v", err)
	}

	if err := repo.UpsertAssetIdentifiers(ctx, correlation.UpsertAssetIdentifiersParams{
		AssetID:       asset.ID,
		SiteID:        site.ID,
		ObservationID: observation.ID,
		FirstSeen:     observedAt,
		LastSeen:      observedAt,
		Identifiers: []correlation.Identifier{
			{Kind: correlation.IdentifierKindHostname, Value: "host-1"},
			{Kind: correlation.IdentifierKindSerialNumber, Value: "ser-001"},
		},
	}); err != nil {
		t.Fatalf("UpsertAssetIdentifiers returned error: %v", err)
	}

	if err := repo.UpsertAssetAddresses(ctx, correlation.UpsertAssetAddressesParams{
		AssetID:       asset.ID,
		SiteID:        site.ID,
		ObservationID: observation.ID,
		FirstSeen:     observedAt,
		LastSeen:      observedAt,
		Addresses: []correlation.Address{
			{Type: correlation.AddressTypeIP, Value: "192.0.2.10"},
			{Type: correlation.AddressTypeMAC, Value: "aa:bb:cc:dd:ee:ff"},
		},
	}); err != nil {
		t.Fatalf("UpsertAssetAddresses returned error: %v", err)
	}

	if err := repo.CreateSighting(ctx, correlation.CreateSightingParams{
		AssetID:          asset.ID,
		SiteID:           site.ID,
		ObservationID:    observation.ID,
		ObservationType:  observation.Type,
		ObservationScope: observation.Scope,
		NodeID:           &node.ID,
		ObservedAt:       observedAt,
		Confidence:       0.9,
		SourceProtocol:   "ssh",
	}); err != nil {
		t.Fatalf("CreateSighting returned error: %v", err)
	}

	assets, err := repo.ListAssets(ctx, ListAssetsParams{SiteID: site.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}

	if len(assets) != 1 {
		t.Fatalf("len(assets) = %d, want %d", len(assets), 1)
	}

	if assets[0].SerialNumber != "ser-001" {
		t.Fatalf("assets[0].SerialNumber = %q, want %q", assets[0].SerialNumber, "ser-001")
	}

	detail, err := repo.GetAssetDetail(ctx, asset.ID)
	if err != nil {
		t.Fatalf("GetAssetDetail returned error: %v", err)
	}

	if len(detail.Identifiers) != 2 {
		t.Fatalf("len(detail.Identifiers) = %d, want %d", len(detail.Identifiers), 2)
	}

	if len(detail.Addresses) != 2 {
		t.Fatalf("len(detail.Addresses) = %d, want %d", len(detail.Addresses), 2)
	}

	if len(detail.Sightings) != 1 {
		t.Fatalf("len(detail.Sightings) = %d, want %d", len(detail.Sightings), 1)
	}

	if detail.Sightings[0].ObservationID != observation.ID {
		t.Fatalf("detail.Sightings[0].ObservationID = %q, want %q", detail.Sightings[0].ObservationID, observation.ID)
	}
}

func TestRepositoryListRecentObservationsIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openIntegrationPool(t, ctx)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := NewRepository(tx)
	site, node := createSiteAndCollector(t, ctx, repo)
	job, err := repo.CreateJob(ctx, CreateJobParams{
		SiteID:     site.ID,
		Kind:       "demo",
		Capability: "icmp",
		Status:     jobtypes.StatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	firstObservedAt := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	secondObservedAt := firstObservedAt.Add(5 * time.Minute)

	firstPayload := mustMarshalObservation(t, observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          "icmp.alive",
		Scope:         "sighting",
		SiteID:        site.ID,
		JobID:         job.ID,
		Emitter: &observations.Emitter{
			Kind:       "collector",
			ID:         node.ID,
			Name:       node.Name,
			Version:    node.Version,
			Capability: "icmp",
		},
		ObservedAt: firstObservedAt,
		Facts:      map[string]any{"sequence": 1},
		Evidence:   &observations.Evidence{Confidence: 0.8, SourceProtocol: "icmp"},
	})

	secondPayload := mustMarshalObservation(t, observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          "icmp.alive",
		Scope:         "sighting",
		SiteID:        site.ID,
		JobID:         job.ID,
		Emitter: &observations.Emitter{
			Kind:       "collector",
			ID:         node.ID,
			Name:       node.Name,
			Version:    node.Version,
			Capability: "icmp",
		},
		ObservedAt: secondObservedAt,
		Facts:      map[string]any{"sequence": 2},
		Evidence:   &observations.Evidence{Confidence: 0.9, SourceProtocol: "icmp"},
	})

	first, err := repo.CreateObservation(ctx, CreateObservationParams{
		SiteID:     site.ID,
		JobID:      &job.ID,
		NodeID:     &node.ID,
		Type:       "icmp.alive",
		Scope:      "sighting",
		ObservedAt: firstObservedAt,
		Payload:    firstPayload,
	})
	if err != nil {
		t.Fatalf("CreateObservation(first) returned error: %v", err)
	}

	second, err := repo.CreateObservation(ctx, CreateObservationParams{
		SiteID:     site.ID,
		JobID:      &job.ID,
		NodeID:     &node.ID,
		Type:       "icmp.alive",
		Scope:      "sighting",
		ObservedAt: secondObservedAt,
		Payload:    secondPayload,
	})
	if err != nil {
		t.Fatalf("CreateObservation(second) returned error: %v", err)
	}

	records, err := repo.ListRecentObservations(ctx, 10)
	if err != nil {
		t.Fatalf("ListRecentObservations returned error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want %d", len(records), 2)
	}

	if records[0].ID != second.ID {
		t.Fatalf("records[0].ID = %q, want %q", records[0].ID, second.ID)
	}

	if records[1].ID != first.ID {
		t.Fatalf("records[1].ID = %q, want %q", records[1].ID, first.ID)
	}

	if records[0].NodeID == nil || *records[0].NodeID != node.ID {
		t.Fatalf("records[0].NodeID = %v, want %q", records[0].NodeID, node.ID)
	}
}

func TestRepositoryCreateSiteRejectsDuplicateSlugIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openIntegrationPool(t, ctx)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := NewRepository(tx)
	slug := fmt.Sprintf("site-%s", uuid.NewString())

	if _, err := repo.CreateSite(ctx, CreateSiteParams{Slug: slug, Name: "Site A"}); err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	if _, err := repo.CreateSite(ctx, CreateSiteParams{Slug: slug, Name: "Site B"}); err == nil {
		t.Fatal("CreateSite returned nil error, want duplicate slug error")
	}
}

func openIntegrationPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set TEST_DB_DSN to run PostgreSQL integration tests")
	}

	pool, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := ApplyMigrations(ctx, pool, logger); err != nil {
		pool.Close()
		t.Fatalf("ApplyMigrations returned error: %v", err)
	}

	t.Cleanup(pool.Close)
	return pool
}

func assertRecordExists(t *testing.T, ctx context.Context, tx pgx.Tx, query string, id string, want string) {
	t.Helper()

	var got string
	if err := tx.QueryRow(ctx, query, id).Scan(&got); err != nil {
		t.Fatalf("QueryRow returned error: %v", err)
	}

	if got != want {
		t.Fatalf("value = %q, want %q", got, want)
	}
}

func createSiteAndCollector(t *testing.T, ctx context.Context, repo *Repository) (Site, Node) {
	t.Helper()

	slug := fmt.Sprintf("site-%s", uuid.NewString())
	site, err := repo.CreateSite(ctx, CreateSiteParams{Slug: slug, Name: "Test Site"})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	node, err := repo.CreateNode(ctx, CreateNodeParams{
		SiteID:        site.ID,
		Kind:          NodeKindCollector,
		Name:          fmt.Sprintf("collector-%s", uuid.NewString()),
		Version:       "0.1.0",
		Capabilities:  []string{"ssh", "icmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken(uuid.NewString()),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	return site, node
}

func createSiteAndTwoCollectors(t *testing.T, ctx context.Context, repo *Repository) (Site, Node, Node) {
	t.Helper()

	site, nodeA := createSiteAndCollector(t, ctx, repo)
	nodeB, err := repo.CreateNode(ctx, CreateNodeParams{
		SiteID:        site.ID,
		Kind:          NodeKindCollector,
		Name:          fmt.Sprintf("collector-%s", uuid.NewString()),
		Version:       "0.1.0",
		Capabilities:  []string{"ssh", "icmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken(uuid.NewString()),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	return site, nodeA, nodeB
}

func mustMarshalObservation(t *testing.T, observation observations.Observation) json.RawMessage {
	t.Helper()

	payload, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	return payload
}
