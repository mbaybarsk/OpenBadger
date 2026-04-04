package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/auth"
	"github.com/mbaybarsk/openbadger/internal/correlation"
	"github.com/mbaybarsk/openbadger/internal/credentials"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

func TestNewHandlerHealthz(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want %q", got, "application/json")
	}

	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if payload["status"] != "ok" {
		t.Fatalf("payload status = %q, want %q", payload["status"], "ok")
	}
}

func TestNewHandlerReadyz(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if payload["status"] != "ready" {
		t.Fatalf("payload status = %q, want %q", payload["status"], "ready")
	}
}

func TestNewHandlerRejectsNonGet(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()

	NewHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestNodeEnrollHandlerIssuesNodeToken(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	handler := newHandler(HandlerOptions{
		NodeService: newNodeService(store, "bootstrap-token", func() time.Time {
			return time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC)
		}, func() (string, error) {
			return "issued-node-token", nil
		}),
	})

	body := strings.NewReader(`{"site_id":"site-1","kind":"collector","name":"collector-1","version":"0.1.0","capabilities":["ssh","snmp","ssh"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/enroll", body)
	req.Header.Set("Authorization", "Bearer bootstrap-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response nodes.EnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.AuthToken != "issued-node-token" {
		t.Fatalf("response.AuthToken = %q, want %q", response.AuthToken, "issued-node-token")
	}

	if len(store.createCalls) != 1 {
		t.Fatalf("createCalls = %d, want %d", len(store.createCalls), 1)
	}

	if store.createCalls[0].AuthTokenHash != auth.HashToken("issued-node-token") {
		t.Fatalf("AuthTokenHash = %q, want hashed token", store.createCalls[0].AuthTokenHash)
	}

	if got := fmt.Sprintf("%v", store.createCalls[0].Capabilities); got != "[snmp ssh]" {
		t.Fatalf("Capabilities = %v, want [snmp ssh]", store.createCalls[0].Capabilities)
	}
}

func TestNodeHeartbeatHandlerUpdatesNode(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	_, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	fixedNow := time.Date(2026, time.April, 4, 9, 5, 0, 0, time.UTC)
	handler := newHandler(HandlerOptions{
		NodeService: newNodeService(store, "bootstrap-token", func() time.Time { return fixedNow }, nil),
	})

	body := strings.NewReader(`{"name":"collector-1-renamed","version":"0.1.1","capabilities":["icmp","ssh"],"health_status":"healthy"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/heartbeat", body)
	req.Header.Set("Authorization", "Bearer node-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response nodes.HeartbeatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.Name != "collector-1-renamed" {
		t.Fatalf("response.Name = %q, want %q", response.Name, "collector-1-renamed")
	}

	if !response.LastHeartbeatAt.Equal(fixedNow) {
		t.Fatalf("response.LastHeartbeatAt = %s, want %s", response.LastHeartbeatAt, fixedNow)
	}
}

func TestNodeHeartbeatHandlerRejectsInvalidToken(t *testing.T) {
	t.Parallel()

	handler := newHandler(HandlerOptions{
		NodeService: newNodeService(newMemoryNodeStore(), "bootstrap-token", nil, nil),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/heartbeat", strings.NewReader(`{"name":"collector-1"}`))
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJobLeaseHandlerReturnsEligibleJob(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	_, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh", "icmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	if _, err := store.CreateJob(context.Background(), postgres.CreateJobParams{
		SiteID:     "site-1",
		Kind:       "scan",
		Capability: "ssh",
		Status:     jobtypes.StatusQueued,
	}); err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{
		NodeService: newNodeService(store, "bootstrap-token", nil, nil),
		JobService:  newJobService(store, func() time.Time { return time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC) }),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/lease", strings.NewReader(`{"lease_duration_seconds":45}`))
	req.Header.Set("Authorization", "Bearer node-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response jobtypes.LeaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.Job.Status != jobtypes.StatusRunning {
		t.Fatalf("response.Job.Status = %q, want %q", response.Job.Status, jobtypes.StatusRunning)
	}

	if response.Job.LeaseOwnerNodeID == nil || *response.Job.LeaseOwnerNodeID == "" {
		t.Fatalf("response.Job.LeaseOwnerNodeID = %v, want non-empty lease owner", response.Job.LeaseOwnerNodeID)
	}
}

func TestJobLeaseHandlerReturnsNoContentWhenNoEligibleJob(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	_, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{
		JobService: newJobService(store, nil),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/lease", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer node-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestJobStatusHandlerUpdatesJob(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	createdNode, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	createdJob, err := store.CreateJob(context.Background(), postgres.CreateJobParams{
		SiteID:     "site-1",
		Kind:       "scan",
		Capability: "ssh",
		Status:     jobtypes.StatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	if _, err := store.LeaseJob(context.Background(), postgres.LeaseJobParams{
		SiteID:        "site-1",
		NodeID:        createdNode.ID,
		Capabilities:  []string{"ssh"},
		LeaseDuration: 30 * time.Second,
		Now:           time.Date(2026, time.April, 4, 10, 10, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("LeaseJob returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{
		JobService: newJobService(store, func() time.Time { return time.Date(2026, time.April, 4, 10, 10, 5, 0, time.UTC) }),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+createdJob.ID+"/status", strings.NewReader(`{"status":"success"}`))
	req.Header.Set("Authorization", "Bearer node-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response jobtypes.StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.Job.Status != jobtypes.StatusSuccess {
		t.Fatalf("response.Job.Status = %q, want %q", response.Job.Status, jobtypes.StatusSuccess)
	}

	if response.Job.CompletedAt == nil {
		t.Fatal("response.Job.CompletedAt = nil, want timestamp")
	}
}

func TestJobStatusHandlerRejectsInvalidTransition(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	createdNode, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	createdJob, err := store.CreateJob(context.Background(), postgres.CreateJobParams{
		SiteID:     "site-1",
		Kind:       "scan",
		Capability: "ssh",
		Status:     jobtypes.StatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	if _, err := store.LeaseJob(context.Background(), postgres.LeaseJobParams{
		SiteID:        "site-1",
		NodeID:        createdNode.ID,
		Capabilities:  []string{"ssh"},
		LeaseDuration: 30 * time.Second,
		Now:           time.Date(2026, time.April, 4, 10, 15, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("LeaseJob returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{
		JobService: newJobService(store, func() time.Time { return time.Date(2026, time.April, 4, 10, 15, 5, 0, time.UTC) }),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+createdJob.ID+"/status", strings.NewReader(`{"status":"running"}`))
	req.Header.Set("Authorization", "Bearer node-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestDebugJobsHandlerCreatesQueuedJob(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	handler := newHandler(HandlerOptions{
		JobService: newJobService(store, nil),
	})

	req := httptest.NewRequest(http.MethodPost, "/debug/jobs", strings.NewReader(`{"site_id":"site-1","capability":"ssh"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response jobtypes.DebugCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.Job.Status != jobtypes.StatusQueued {
		t.Fatalf("response.Job.Status = %q, want %q", response.Job.Status, jobtypes.StatusQueued)
	}

	if response.Job.Capability != "ssh" {
		t.Fatalf("response.Job.Capability = %q, want %q", response.Job.Capability, "ssh")
	}
}

func TestObservationBatchHandlerStoresValidatedObservations(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	_, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"icmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{
		ObservationService: newObservationService(store),
	})

	body, err := json.Marshal(observations.BatchRequest{
		Observations: []observations.Observation{{
			SchemaVersion: observations.SchemaVersion,
			ObservationID: "obs-1",
			Type:          "icmp.alive",
			Scope:         "sighting",
			SiteID:        "site-1",
			JobID:         "job-1",
			Emitter: &observations.Emitter{
				Kind:       "collector",
				ID:         "node-1",
				Name:       "collector-1",
				Version:    "0.1.0",
				Capability: "icmp",
			},
			ObservedAt: time.Date(2026, time.April, 4, 12, 30, 0, 0, time.UTC),
			Facts:      map[string]any{"rtt_ms": 1.2},
			Evidence:   &observations.Evidence{Confidence: 0.9, SourceProtocol: "icmp"},
		}},
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/observations/batch", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer node-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}

	var response observations.BatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.Accepted != 1 {
		t.Fatalf("response.Accepted = %d, want %d", response.Accepted, 1)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.observations) != 1 {
		t.Fatalf("len(store.observations) = %d, want %d", len(store.observations), 1)
	}

	if store.observations[0].ID != "obs-1" {
		t.Fatalf("store.observations[0].ID = %q, want %q", store.observations[0].ID, "obs-1")
	}

	if store.observations[0].NodeID == nil || *store.observations[0].NodeID == "" {
		t.Fatalf("store.observations[0].NodeID = %v, want non-empty node id", store.observations[0].NodeID)
	}
	if store.observations[0].JobID == nil || *store.observations[0].JobID != "job-1" {
		t.Fatalf("store.observations[0].JobID = %v, want %q", store.observations[0].JobID, "job-1")
	}
}

func TestObservationBatchHandlerRejectsInvalidObservation(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	_, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"icmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("node-token"),
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{
		ObservationService: newObservationService(store),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/observations/batch", strings.NewReader(`{"observations":[{"observation_id":"obs-1","type":"icmp.alive","scope":"sighting","site_id":"site-1","emitter":{"kind":"collector"},"observed_at":"2026-04-04T12:30:00Z","facts":{},"evidence":{}}]}`))
	req.Header.Set("Authorization", "Bearer node-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDebugObservationsHandlerReturnsRecentObservations(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	_, err := store.CreateObservation(context.Background(), postgres.CreateObservationParams{
		ID:         "obs-1",
		SiteID:     "site-1",
		Type:       "icmp.alive",
		Scope:      "sighting",
		ObservedAt: time.Date(2026, time.April, 4, 12, 35, 0, 0, time.UTC),
		Payload:    json.RawMessage(`{"observation_id":"obs-1"}`),
	})
	if err != nil {
		t.Fatalf("CreateObservation returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{
		ObservationService: newObservationService(store),
	})

	req := httptest.NewRequest(http.MethodGet, "/debug/observations?limit=5", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response struct {
		Observations []postgres.Observation `json:"observations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if len(response.Observations) != 1 {
		t.Fatalf("len(response.Observations) = %d, want %d", len(response.Observations), 1)
	}

	if response.Observations[0].ID != "obs-1" {
		t.Fatalf("response.Observations[0].ID = %q, want %q", response.Observations[0].ID, "obs-1")
	}
}

type memoryNodeStore struct {
	mu                        sync.Mutex
	sequence                  int
	byID                      map[string]nodes.Record
	byTokenHash               map[string]string
	createCalls               []nodes.CreateParams
	jobSequence               int
	jobsByID                  map[string]jobtypes.Record
	jobOrder                  []string
	observations              []postgres.Observation
	assetSequence             int
	assetsByID                map[string]correlation.Asset
	assetIdentifiersByAsset   map[string][]postgres.AssetIdentifier
	assetAddressesByAsset     map[string][]postgres.AssetAddress
	sightingsByAsset          map[string][]postgres.Sighting
	targetRangeSequence       int
	targetRangesByID          map[string]targets.Record
	credentialProfileSequence int
	credentialProfilesByID    map[string]credentials.Profile
	scanProfileSequence       int
	scanProfilesByID          map[string]profiles.ScanProfile
	scheduleSequence          int
	schedulesByID             map[string]schedules.Record
}

func newMemoryNodeStore() *memoryNodeStore {
	return &memoryNodeStore{
		byID:                    make(map[string]nodes.Record),
		byTokenHash:             make(map[string]string),
		jobsByID:                make(map[string]jobtypes.Record),
		assetsByID:              make(map[string]correlation.Asset),
		assetIdentifiersByAsset: make(map[string][]postgres.AssetIdentifier),
		assetAddressesByAsset:   make(map[string][]postgres.AssetAddress),
		sightingsByAsset:        make(map[string][]postgres.Sighting),
		targetRangesByID:        make(map[string]targets.Record),
		credentialProfilesByID:  make(map[string]credentials.Profile),
		scanProfilesByID:        make(map[string]profiles.ScanProfile),
		schedulesByID:           make(map[string]schedules.Record),
	}
}

func (s *memoryNodeStore) CreateNode(_ context.Context, params nodes.CreateParams) (nodes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, record := range s.byID {
		if record.SiteID == strings.TrimSpace(params.SiteID) && record.Name == strings.TrimSpace(params.Name) {
			return nodes.Record{}, fmt.Errorf("node name already exists for site: %w", nodes.ErrConflict)
		}
	}

	s.sequence++
	now := time.Date(2026, time.April, 4, 8, 59, 0, 0, time.UTC)
	record := nodes.Record{
		ID:              fmt.Sprintf("node-%d", s.sequence),
		SiteID:          strings.TrimSpace(params.SiteID),
		Kind:            nodes.NormalizeKind(string(params.Kind)),
		Name:            strings.TrimSpace(params.Name),
		Version:         strings.TrimSpace(params.Version),
		Capabilities:    nodes.NormalizeCapabilities(params.Capabilities),
		HealthStatus:    strings.TrimSpace(params.HealthStatus),
		LastHeartbeatAt: params.LastHeartbeatAt,
		AuthTokenHash:   strings.TrimSpace(params.AuthTokenHash),
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if record.HealthStatus == "" {
		record.HealthStatus = "healthy"
	}

	s.byID[record.ID] = record
	s.byTokenHash[record.AuthTokenHash] = record.ID
	s.createCalls = append(s.createCalls, params)

	return record, nil
}

func (s *memoryNodeStore) GetNodeByAuthTokenHash(_ context.Context, tokenHash string) (nodes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeID, ok := s.byTokenHash[strings.TrimSpace(tokenHash)]
	if !ok {
		return nodes.Record{}, nodes.ErrNotFound
	}

	return s.byID[nodeID], nil
}

func (s *memoryNodeStore) UpdateNodeHeartbeat(_ context.Context, params nodes.HeartbeatParams) (nodes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.byID[strings.TrimSpace(params.NodeID)]
	if !ok {
		return nodes.Record{}, nodes.ErrNotFound
	}

	record.Name = strings.TrimSpace(params.Name)
	record.Version = strings.TrimSpace(params.Version)
	record.Capabilities = nodes.NormalizeCapabilities(params.Capabilities)
	record.HealthStatus = strings.TrimSpace(params.HealthStatus)
	if record.HealthStatus == "" {
		record.HealthStatus = "healthy"
	}
	record.LastHeartbeatAt = &params.LastHeartbeatAt
	record.UpdatedAt = params.LastHeartbeatAt
	s.byID[record.ID] = record

	return record, nil
}

func (s *memoryNodeStore) ListNodes(_ context.Context) ([]nodes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	records := make([]nodes.Record, 0, len(s.byID))
	for _, record := range s.byID {
		records = append(records, record)
	}

	return records, nil
}

func (s *memoryNodeStore) CreateJob(_ context.Context, params postgres.CreateJobParams) (jobtypes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobSequence++
	now := time.Date(2026, time.April, 4, 9, 30, 0, 0, time.UTC)
	status := jobtypes.NormalizeStatus(string(params.Status))
	if status == "" {
		status = jobtypes.StatusQueued
	}

	record := jobtypes.Record{
		ID:         fmt.Sprintf("job-%d", s.jobSequence),
		SiteID:     strings.TrimSpace(params.SiteID),
		Kind:       strings.TrimSpace(params.Kind),
		Capability: strings.ToLower(strings.TrimSpace(params.Capability)),
		Payload:    append(json.RawMessage(nil), params.Payload...),
		Status:     status,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if params.NodeID != nil {
		nodeID := strings.TrimSpace(*params.NodeID)
		if nodeID != "" {
			record.NodeID = &nodeID
		}
	}

	s.jobsByID[record.ID] = record
	s.jobOrder = append(s.jobOrder, record.ID)

	return record, nil
}

func (s *memoryNodeStore) LeaseJob(_ context.Context, params postgres.LeaseJobParams) (jobtypes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC)
	}

	leaseDuration := params.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}

	capabilities := nodes.NormalizeCapabilities(params.Capabilities)
	for _, jobID := range s.jobOrder {
		job := s.jobsByID[jobID]
		if strings.TrimSpace(job.SiteID) != strings.TrimSpace(params.SiteID) {
			continue
		}

		if !contains(capabilities, job.Capability) {
			continue
		}

		if job.Status != jobtypes.StatusQueued && job.Status != jobtypes.StatusRunning {
			continue
		}

		if job.LeaseExpiresAt != nil && job.LeaseExpiresAt.After(now) {
			continue
		}

		nodeID := strings.TrimSpace(params.NodeID)
		leaseExpiresAt := now.Add(leaseDuration)
		job.NodeID = &nodeID
		job.LeaseOwnerNodeID = &nodeID
		job.LeaseExpiresAt = &leaseExpiresAt
		job.Status = jobtypes.StatusRunning
		if job.StartedAt == nil {
			job.StartedAt = timeRef(now)
		}
		job.UpdatedAt = now
		s.jobsByID[jobID] = job

		return job, nil
	}

	return jobtypes.Record{}, jobtypes.ErrLeaseUnavailable
}

func (s *memoryNodeStore) UpdateJobStatus(_ context.Context, params postgres.UpdateJobStatusParams) (jobtypes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.jobsByID[strings.TrimSpace(params.JobID)]
	if !ok {
		return jobtypes.Record{}, jobtypes.ErrNotFound
	}

	nodeID := strings.TrimSpace(params.NodeID)
	if job.LeaseOwnerNodeID == nil || strings.TrimSpace(*job.LeaseOwnerNodeID) != nodeID {
		return jobtypes.Record{}, jobtypes.ErrLeaseOwnerMismatch
	}

	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Date(2026, time.April, 4, 10, 0, 5, 0, time.UTC)
	}

	if job.LeaseExpiresAt == nil || !job.LeaseExpiresAt.After(now) {
		return jobtypes.Record{}, jobtypes.ErrLeaseUnavailable
	}

	status := jobtypes.NormalizeStatus(string(params.Status))
	if err := jobtypes.ValidateTransition(job.Status, status); err != nil {
		return jobtypes.Record{}, err
	}

	job.Status = status
	job.ErrorSummary = strings.TrimSpace(params.ErrorSummary)
	job.UpdatedAt = now
	if job.Status == jobtypes.StatusSuccess {
		job.ErrorSummary = ""
	}
	if job.Status == jobtypes.StatusSuccess || job.Status == jobtypes.StatusFailed {
		job.LeaseOwnerNodeID = nil
		job.LeaseExpiresAt = nil
		job.CompletedAt = timeRef(now)
	}
	job.NodeID = &nodeID
	if job.StartedAt == nil {
		job.StartedAt = timeRef(now)
	}

	s.jobsByID[job.ID] = job
	return job, nil
}

func (s *memoryNodeStore) CreateObservation(_ context.Context, params postgres.CreateObservationParams) (postgres.Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := postgres.Observation{
		ID:         strings.TrimSpace(params.ID),
		SiteID:     strings.TrimSpace(params.SiteID),
		JobID:      params.JobID,
		NodeID:     params.NodeID,
		Type:       strings.TrimSpace(params.Type),
		Scope:      strings.TrimSpace(params.Scope),
		ObservedAt: params.ObservedAt.UTC(),
		Payload:    append(json.RawMessage(nil), params.Payload...),
		CreatedAt:  time.Date(2026, time.April, 4, 12, 31, len(s.observations), 0, time.UTC),
	}

	s.observations = append(s.observations, record)
	return record, nil
}

func (s *memoryNodeStore) ListRecentObservations(_ context.Context, limit int) ([]postgres.Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	records := append([]postgres.Observation(nil), s.observations...)
	for i := 0; i < len(records)-1; i++ {
		for j := i + 1; j < len(records); j++ {
			if records[j].ObservedAt.After(records[i].ObservedAt) {
				records[i], records[j] = records[j], records[i]
			}
		}
	}

	if len(records) > limit {
		records = records[:limit]
	}

	return records, nil
}

func (s *memoryNodeStore) DeleteObservationsBefore(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := make([]postgres.Observation, 0, len(s.observations))
	deleted := int64(0)
	for _, observation := range s.observations {
		if observation.ObservedAt.Before(cutoff) {
			deleted++
			continue
		}
		kept = append(kept, observation)
	}

	s.observations = kept
	return deleted, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func timeRef(value time.Time) *time.Time {
	copy := value
	return &copy
}
