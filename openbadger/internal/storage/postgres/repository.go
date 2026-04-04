package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mbaybarsk/openbadger/internal/credentials"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
)

type DBTX interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Repository struct {
	db        DBTX
	secretBox *credentials.SecretBox
}

func NewRepository(db DBTX) *Repository {
	return NewRepositoryWithOptions(db, RepositoryOptions{})
}

type RepositoryOptions struct {
	SecretBox *credentials.SecretBox
}

func NewRepositoryWithOptions(db DBTX, options RepositoryOptions) *Repository {
	return &Repository{db: db, secretBox: options.SecretBox}
}

type Site struct {
	ID          string
	Slug        string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type CreateSiteParams struct {
	Slug        string
	Name        string
	Description string
}

type NodeKind = nodes.Kind

const (
	NodeKindCollector NodeKind = nodes.KindCollector
	NodeKindSensor    NodeKind = nodes.KindSensor
)

type Node = nodes.Record

type CreateNodeParams = nodes.CreateParams

type UpdateNodeHeartbeatParams = nodes.HeartbeatParams

type Job = jobtypes.Record

type CreateJobParams struct {
	SiteID           string
	NodeID           *string
	Kind             string
	Capability       string
	Payload          json.RawMessage
	Status           jobtypes.Status
	LeaseOwnerNodeID *string
	LeaseExpiresAt   *time.Time
	ErrorSummary     string
	StartedAt        *time.Time
	CompletedAt      *time.Time
}

type LeaseJobParams struct {
	SiteID        string
	NodeID        string
	Capabilities  []string
	LeaseDuration time.Duration
	Now           time.Time
}

type UpdateJobStatusParams struct {
	JobID        string
	NodeID       string
	Status       jobtypes.Status
	ErrorSummary string
	Now          time.Time
}

type Observation struct {
	ID         string          `json:"observation_id"`
	SiteID     string          `json:"site_id"`
	JobID      *string         `json:"job_id,omitempty"`
	NodeID     *string         `json:"node_id,omitempty"`
	Type       string          `json:"type"`
	Scope      string          `json:"scope"`
	ObservedAt time.Time       `json:"observed_at"`
	Payload    json.RawMessage `json:"payload"`
	CreatedAt  time.Time       `json:"created_at"`
}

type CreateObservationParams struct {
	ID         string
	SiteID     string
	JobID      *string
	NodeID     *string
	Type       string
	Scope      string
	ObservedAt time.Time
	Payload    json.RawMessage
}

func (r *Repository) CreateSite(ctx context.Context, params CreateSiteParams) (Site, error) {
	if r == nil || r.db == nil {
		return Site{}, fmt.Errorf("repository database is required")
	}

	site := Site{
		ID:          uuid.NewString(),
		Slug:        strings.TrimSpace(params.Slug),
		Name:        strings.TrimSpace(params.Name),
		Description: strings.TrimSpace(params.Description),
	}

	if site.Slug == "" {
		return Site{}, fmt.Errorf("site slug is required")
	}

	if site.Name == "" {
		return Site{}, fmt.Errorf("site name is required")
	}

	err := r.db.QueryRow(ctx, `
		INSERT INTO sites (id, slug, name, description)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at, updated_at
	`, site.ID, site.Slug, site.Name, site.Description).Scan(&site.CreatedAt, &site.UpdatedAt)
	if err != nil {
		return Site{}, fmt.Errorf("insert site: %w", err)
	}

	return site, nil
}

func (r *Repository) CreateNode(ctx context.Context, params CreateNodeParams) (Node, error) {
	if r == nil || r.db == nil {
		return Node{}, fmt.Errorf("repository database is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return Node{}, fmt.Errorf("node site id is required")
	}

	kind := nodes.NormalizeKind(string(params.Kind))
	if !nodes.ValidateKind(kind) {
		return Node{}, fmt.Errorf("node kind %q is invalid", params.Kind)
	}

	name := strings.TrimSpace(params.Name)
	if name == "" {
		return Node{}, fmt.Errorf("node name is required")
	}

	healthStatus := strings.TrimSpace(params.HealthStatus)
	if healthStatus == "" {
		healthStatus = "unknown"
	}

	authTokenHash := strings.TrimSpace(params.AuthTokenHash)
	if authTokenHash == "" {
		return Node{}, fmt.Errorf("node auth token hash is required")
	}

	capabilities := normalizeCapabilities(params.Capabilities)
	capabilitiesJSON, err := json.Marshal(capabilities)
	if err != nil {
		return Node{}, fmt.Errorf("marshal node capabilities: %w", err)
	}

	node := Node{
		ID:              uuid.NewString(),
		SiteID:          siteID,
		Kind:            kind,
		Name:            name,
		Version:         strings.TrimSpace(params.Version),
		Capabilities:    capabilities,
		HealthStatus:    healthStatus,
		LastHeartbeatAt: params.LastHeartbeatAt,
		AuthTokenHash:   authTokenHash,
	}

	err = r.db.QueryRow(ctx, `
		INSERT INTO nodes (id, site_id, kind, name, version, capabilities, health_status, last_heartbeat_at, auth_token_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at, updated_at
	`, node.ID, node.SiteID, node.Kind, node.Name, node.Version, capabilitiesJSON, node.HealthStatus, node.LastHeartbeatAt, node.AuthTokenHash).Scan(&node.CreatedAt, &node.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Node{}, fmt.Errorf("node name already exists for site: %w", nodes.ErrConflict)
		}

		return Node{}, fmt.Errorf("insert node: %w", err)
	}

	return node, nil
}

func (r *Repository) GetNodeByAuthTokenHash(ctx context.Context, tokenHash string) (Node, error) {
	if r == nil || r.db == nil {
		return Node{}, fmt.Errorf("repository database is required")
	}

	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return Node{}, fmt.Errorf("node auth token hash is required")
	}

	var capabilitiesJSON []byte
	var node Node
	err := r.db.QueryRow(ctx, `
		SELECT id, site_id, kind, name, version, capabilities, health_status, last_heartbeat_at, auth_token_hash, created_at, updated_at
		FROM nodes
		WHERE auth_token_hash = $1
	`, tokenHash).Scan(
		&node.ID,
		&node.SiteID,
		&node.Kind,
		&node.Name,
		&node.Version,
		&capabilitiesJSON,
		&node.HealthStatus,
		&node.LastHeartbeatAt,
		&node.AuthTokenHash,
		&node.CreatedAt,
		&node.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Node{}, nodes.ErrNotFound
		}

		return Node{}, fmt.Errorf("select node by auth token hash: %w", err)
	}

	if err := json.Unmarshal(capabilitiesJSON, &node.Capabilities); err != nil {
		return Node{}, fmt.Errorf("decode node capabilities: %w", err)
	}

	return node, nil
}

func (r *Repository) UpdateNodeHeartbeat(ctx context.Context, params UpdateNodeHeartbeatParams) (Node, error) {
	if r == nil || r.db == nil {
		return Node{}, fmt.Errorf("repository database is required")
	}

	nodeID := strings.TrimSpace(params.NodeID)
	if nodeID == "" {
		return Node{}, fmt.Errorf("node id is required")
	}

	name := strings.TrimSpace(params.Name)
	if name == "" {
		return Node{}, fmt.Errorf("node name is required")
	}

	healthStatus := strings.TrimSpace(params.HealthStatus)
	if healthStatus == "" {
		healthStatus = "healthy"
	}

	lastHeartbeatAt := params.LastHeartbeatAt.UTC()
	capabilities := normalizeCapabilities(params.Capabilities)
	capabilitiesJSON, err := json.Marshal(capabilities)
	if err != nil {
		return Node{}, fmt.Errorf("marshal node capabilities: %w", err)
	}

	node := Node{
		ID:              nodeID,
		Name:            name,
		Version:         strings.TrimSpace(params.Version),
		Capabilities:    capabilities,
		HealthStatus:    healthStatus,
		LastHeartbeatAt: &lastHeartbeatAt,
	}

	err = r.db.QueryRow(ctx, `
		UPDATE nodes
		SET name = $2,
			version = $3,
			capabilities = $4,
			health_status = $5,
			last_heartbeat_at = $6,
			updated_at = NOW()
		WHERE id = $1
		RETURNING site_id, kind, auth_token_hash, created_at, updated_at
	`, node.ID, node.Name, node.Version, capabilitiesJSON, node.HealthStatus, node.LastHeartbeatAt).Scan(
		&node.SiteID,
		&node.Kind,
		&node.AuthTokenHash,
		&node.CreatedAt,
		&node.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Node{}, nodes.ErrNotFound
		}

		if isUniqueViolation(err) {
			return Node{}, fmt.Errorf("node name already exists for site: %w", nodes.ErrConflict)
		}

		return Node{}, fmt.Errorf("update node heartbeat: %w", err)
	}

	return node, nil
}

func (r *Repository) ListNodes(ctx context.Context) ([]Node, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, site_id, kind, name, version, capabilities, health_status, last_heartbeat_at, auth_token_hash, created_at, updated_at
		FROM nodes
		ORDER BY created_at ASC, id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	result := make([]Node, 0)
	for rows.Next() {
		var capabilitiesJSON []byte
		var node Node
		if err := rows.Scan(
			&node.ID,
			&node.SiteID,
			&node.Kind,
			&node.Name,
			&node.Version,
			&capabilitiesJSON,
			&node.HealthStatus,
			&node.LastHeartbeatAt,
			&node.AuthTokenHash,
			&node.CreatedAt,
			&node.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}

		if err := json.Unmarshal(capabilitiesJSON, &node.Capabilities); err != nil {
			return nil, fmt.Errorf("decode node capabilities: %w", err)
		}

		result = append(result, node)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}

	return result, nil
}

func (r *Repository) CreateJob(ctx context.Context, params CreateJobParams) (Job, error) {
	if r == nil || r.db == nil {
		return Job{}, fmt.Errorf("repository database is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return Job{}, fmt.Errorf("job site id is required")
	}

	kind := strings.TrimSpace(params.Kind)
	if kind == "" {
		return Job{}, fmt.Errorf("job kind is required")
	}

	capability := strings.ToLower(strings.TrimSpace(params.Capability))
	if capability == "" {
		return Job{}, fmt.Errorf("job capability is required")
	}

	payload := append(json.RawMessage(nil), params.Payload...)
	if len(payload) > 0 && !json.Valid(payload) {
		return Job{}, fmt.Errorf("job payload must be valid json")
	}

	storedPayload, err := r.encryptJSONPayload(payload)
	if err != nil {
		return Job{}, err
	}

	status := jobtypes.NormalizeStatus(string(params.Status))
	if status == "" {
		status = jobtypes.StatusQueued
	}

	if !jobtypes.ValidateStatus(status) {
		return Job{}, fmt.Errorf("job status %q is invalid", params.Status)
	}

	var nodeID *string
	if params.NodeID != nil {
		trimmedNodeID := strings.TrimSpace(*params.NodeID)
		if trimmedNodeID != "" {
			nodeID = &trimmedNodeID
		}
	}

	var leaseOwnerNodeID *string
	if params.LeaseOwnerNodeID != nil {
		trimmedLeaseOwnerNodeID := strings.TrimSpace(*params.LeaseOwnerNodeID)
		if trimmedLeaseOwnerNodeID != "" {
			leaseOwnerNodeID = &trimmedLeaseOwnerNodeID
		}
	}

	var leaseExpiresAt *time.Time
	if params.LeaseExpiresAt != nil {
		value := params.LeaseExpiresAt.UTC()
		leaseExpiresAt = &value
	}

	var startedAt *time.Time
	if params.StartedAt != nil {
		value := params.StartedAt.UTC()
		startedAt = &value
	}

	var completedAt *time.Time
	if params.CompletedAt != nil {
		value := params.CompletedAt.UTC()
		completedAt = &value
	}

	job := Job{
		ID:               uuid.NewString(),
		SiteID:           siteID,
		NodeID:           nodeID,
		Kind:             kind,
		Capability:       capability,
		Payload:          payload,
		Status:           status,
		LeaseOwnerNodeID: leaseOwnerNodeID,
		LeaseExpiresAt:   leaseExpiresAt,
		ErrorSummary:     strings.TrimSpace(params.ErrorSummary),
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
	}

	err = r.db.QueryRow(ctx, `
		INSERT INTO jobs (id, site_id, node_id, kind, capability, payload, status, lease_owner_node_id, lease_expires_at, error_summary, started_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING created_at, updated_at
	`, job.ID, job.SiteID, job.NodeID, job.Kind, job.Capability, storedPayload, job.Status, job.LeaseOwnerNodeID, job.LeaseExpiresAt, job.ErrorSummary, job.StartedAt, job.CompletedAt).Scan(&job.CreatedAt, &job.UpdatedAt)
	if err != nil {
		return Job{}, fmt.Errorf("insert job: %w", err)
	}

	return job, nil
}

func (r *Repository) LeaseJob(ctx context.Context, params LeaseJobParams) (Job, error) {
	if r == nil || r.db == nil {
		return Job{}, fmt.Errorf("repository database is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return Job{}, fmt.Errorf("job site id is required")
	}

	nodeID := strings.TrimSpace(params.NodeID)
	if nodeID == "" {
		return Job{}, fmt.Errorf("job node id is required")
	}

	capabilities := normalizeCapabilities(params.Capabilities)
	if len(capabilities) == 0 {
		return Job{}, jobtypes.ErrLeaseUnavailable
	}

	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	leaseDuration := params.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}

	leaseExpiresAt := now.Add(leaseDuration)

	job, err := scanJob(r.db.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id
			FROM jobs
			WHERE site_id = $1
			  AND capability = ANY($2)
			  AND status IN ('queued', 'running')
			  AND (lease_expires_at IS NULL OR lease_expires_at <= $3)
			ORDER BY created_at ASC, id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE jobs AS j
		SET node_id = $4,
			status = CASE WHEN j.status = 'queued' THEN 'running' ELSE j.status END,
			lease_owner_node_id = $4,
			lease_expires_at = $5,
			started_at = CASE WHEN j.started_at IS NULL THEN $3 ELSE j.started_at END,
			updated_at = $3
		FROM candidate
		WHERE j.id = candidate.id
		RETURNING j.id, j.site_id, j.node_id, j.kind, j.capability, j.payload, j.status, j.lease_owner_node_id, j.lease_expires_at, j.error_summary, j.created_at, j.started_at, j.completed_at, j.updated_at
	`, siteID, capabilities, now, nodeID, leaseExpiresAt))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, jobtypes.ErrLeaseUnavailable
		}

		return Job{}, fmt.Errorf("lease job: %w", err)
	}

	job.Payload, err = r.decryptJSONPayload(job.Payload)
	if err != nil {
		return Job{}, err
	}

	return job, nil
}

func (r *Repository) UpdateJobStatus(ctx context.Context, params UpdateJobStatusParams) (Job, error) {
	if r == nil || r.db == nil {
		return Job{}, fmt.Errorf("repository database is required")
	}

	jobID := strings.TrimSpace(params.JobID)
	if jobID == "" {
		return Job{}, fmt.Errorf("job id is required")
	}

	nodeID := strings.TrimSpace(params.NodeID)
	if nodeID == "" {
		return Job{}, fmt.Errorf("job node id is required")
	}

	status := jobtypes.NormalizeStatus(string(params.Status))
	if !jobtypes.ValidateStatus(status) {
		return Job{}, fmt.Errorf("job status %q is invalid", params.Status)
	}

	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var currentStatus jobtypes.Status
	var leaseOwnerNodeID *string
	var leaseExpiresAt *time.Time
	err := r.db.QueryRow(ctx, `
		SELECT status, lease_owner_node_id, lease_expires_at
		FROM jobs
		WHERE id = $1
	`, jobID).Scan(&currentStatus, &leaseOwnerNodeID, &leaseExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, jobtypes.ErrNotFound
		}

		return Job{}, fmt.Errorf("select job: %w", err)
	}

	if leaseOwnerNodeID == nil || strings.TrimSpace(*leaseOwnerNodeID) != nodeID {
		return Job{}, jobtypes.ErrLeaseOwnerMismatch
	}

	if leaseExpiresAt == nil || !leaseExpiresAt.After(now) {
		return Job{}, jobtypes.ErrLeaseUnavailable
	}

	if err := jobtypes.ValidateTransition(currentStatus, status); err != nil {
		return Job{}, err
	}

	errorSummary := strings.TrimSpace(params.ErrorSummary)
	if status == jobtypes.StatusSuccess {
		errorSummary = ""
	}

	job, err := scanJob(r.db.QueryRow(ctx, `
		UPDATE jobs
		SET node_id = $5,
			status = $2,
			error_summary = $3,
			started_at = CASE WHEN $2 = 'running' AND started_at IS NULL THEN $4 ELSE started_at END,
			completed_at = CASE WHEN $2 IN ('success', 'failed') THEN $4 ELSE completed_at END,
			lease_owner_node_id = CASE WHEN $2 IN ('success', 'failed') THEN NULL ELSE lease_owner_node_id END,
			lease_expires_at = CASE WHEN $2 IN ('success', 'failed') THEN NULL ELSE lease_expires_at END,
			updated_at = $4
		WHERE id = $1
		RETURNING id, site_id, node_id, kind, capability, payload, status, lease_owner_node_id, lease_expires_at, error_summary, created_at, started_at, completed_at, updated_at
	`, jobID, status, errorSummary, now, nodeID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, jobtypes.ErrNotFound
		}

		return Job{}, fmt.Errorf("update job status: %w", err)
	}

	job.Payload, err = r.decryptJSONPayload(job.Payload)
	if err != nil {
		return Job{}, err
	}

	return job, nil
}

func (r *Repository) ListJobs(ctx context.Context, limit int) ([]Job, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, site_id, node_id, kind, capability, payload, status, lease_owner_node_id, lease_expires_at, error_summary, created_at, started_at, completed_at, updated_at
		FROM jobs
		ORDER BY created_at DESC, id DESC
		LIMIT $1
	`, normalizeJobListLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer rows.Close()

	jobs := make([]Job, 0)
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan job: %w", err)
		}

		job.Payload, err = r.decryptJSONPayload(job.Payload)
		if err != nil {
			return nil, err
		}

		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate jobs: %w", err)
	}

	return jobs, nil
}

func (r *Repository) CreateObservation(ctx context.Context, params CreateObservationParams) (Observation, error) {
	if r == nil || r.db == nil {
		return Observation{}, fmt.Errorf("repository database is required")
	}

	observationID := strings.TrimSpace(params.ID)
	if observationID == "" {
		observationID = uuid.NewString()
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return Observation{}, fmt.Errorf("observation site id is required")
	}

	observationType := strings.TrimSpace(params.Type)
	if observationType == "" {
		return Observation{}, fmt.Errorf("observation type is required")
	}

	scope := strings.ToLower(strings.TrimSpace(params.Scope))
	if scope != "asset" && scope != "sighting" && scope != "relationship" {
		return Observation{}, fmt.Errorf("observation scope %q is invalid", params.Scope)
	}

	if params.ObservedAt.IsZero() {
		return Observation{}, fmt.Errorf("observation observed_at is required")
	}

	payload := append(json.RawMessage(nil), params.Payload...)
	if len(payload) == 0 {
		return Observation{}, fmt.Errorf("observation payload is required")
	}

	jobID := trimOptionalStringPointer(params.JobID)
	nodeID := trimOptionalStringPointer(params.NodeID)

	observation := Observation{
		ID:         observationID,
		SiteID:     siteID,
		JobID:      jobID,
		NodeID:     nodeID,
		Type:       observationType,
		Scope:      scope,
		ObservedAt: params.ObservedAt.UTC(),
		Payload:    payload,
	}

	err := r.db.QueryRow(ctx, `
		INSERT INTO observations (observation_id, site_id, job_id, node_id, type, scope, observed_at, payload)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at
	`, observation.ID, observation.SiteID, observation.JobID, observation.NodeID, observation.Type, observation.Scope, observation.ObservedAt, observation.Payload).Scan(&observation.CreatedAt)
	if err != nil {
		return Observation{}, fmt.Errorf("insert observation: %w", err)
	}

	return observation, nil
}

func (r *Repository) ListRecentObservations(ctx context.Context, limit int) ([]Observation, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	rows, err := r.db.Query(ctx, `
		SELECT observation_id, site_id, job_id, node_id, type, scope, observed_at, payload, created_at
		FROM observations
		ORDER BY observed_at DESC, created_at DESC
		LIMIT $1
	`, normalizeObservationLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list recent observations: %w", err)
	}
	defer rows.Close()

	observations := make([]Observation, 0)
	for rows.Next() {
		var observation Observation
		if err := rows.Scan(
			&observation.ID,
			&observation.SiteID,
			&observation.JobID,
			&observation.NodeID,
			&observation.Type,
			&observation.Scope,
			&observation.ObservedAt,
			&observation.Payload,
			&observation.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan observation: %w", err)
		}

		observations = append(observations, observation)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate observations: %w", err)
	}

	return observations, nil
}

func (r *Repository) DeleteObservationsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if r == nil || r.db == nil {
		return 0, fmt.Errorf("repository database is required")
	}

	if cutoff.IsZero() {
		return 0, fmt.Errorf("observation retention cutoff is required")
	}

	result, err := r.db.Exec(ctx, `
		DELETE FROM observations
		WHERE observed_at < $1
	`, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("delete observations before cutoff: %w", err)
	}

	return result.RowsAffected(), nil
}

func (r *Repository) encryptJSONPayload(payload []byte) ([]byte, error) {
	payload = append([]byte(nil), payload...)
	if r == nil || r.secretBox == nil || len(payload) == 0 {
		return payload, nil
	}

	encrypted, err := r.secretBox.EncryptJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt stored payload: %w", err)
	}

	return encrypted, nil
}

func (r *Repository) decryptJSONPayload(payload []byte) ([]byte, error) {
	payload = append([]byte(nil), payload...)
	if r == nil || len(payload) == 0 {
		return payload, nil
	}

	if r.secretBox == nil {
		return payload, nil
	}

	decrypted, err := r.secretBox.DecryptStoredJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt stored payload: %w", err)
	}

	return decrypted, nil
}

func normalizeCapabilities(capabilities []string) []string {
	return nodes.NormalizeCapabilities(capabilities)
}

func normalizeObservationLimit(limit int) int {
	if limit <= 0 {
		return 20
	}

	if limit > 100 {
		return 100
	}

	return limit
}

func normalizeJobListLimit(limit int) int {
	if limit <= 0 {
		return 100
	}

	if limit > 500 {
		return 500
	}

	return limit
}

func trimOptionalStringPointer(value *string) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(row rowScanner) (Job, error) {
	var job Job
	var payload []byte
	err := row.Scan(
		&job.ID,
		&job.SiteID,
		&job.NodeID,
		&job.Kind,
		&job.Capability,
		&payload,
		&job.Status,
		&job.LeaseOwnerNodeID,
		&job.LeaseExpiresAt,
		&job.ErrorSummary,
		&job.CreatedAt,
		&job.StartedAt,
		&job.CompletedAt,
		&job.UpdatedAt,
	)
	if err != nil {
		return Job{}, err
	}

	job.Payload = append(json.RawMessage(nil), payload...)

	return job, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
