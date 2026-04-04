package collector

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/config"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

func TestRunPersistsAssignedNodeState(t *testing.T) {
	t.Parallel()

	store := newCollectorMemoryNodeStore()
	httpServer := httptest.NewServer(store.handler())
	defer httpServer.Close()

	statePath := filepath.Join(t.TempDir(), "collector-state.json")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- Run(ctx, config.CollectorConfig{
			Name:              "collector-a",
			ServerURL:         httpServer.URL,
			SiteID:            "site-1",
			EnrollmentToken:   "bootstrap-token",
			StatePath:         statePath,
			HeartbeatInterval: 10 * time.Millisecond,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		state, err := nodes.LoadState(statePath)
		if err == nil {
			if state.NodeID == "" || state.AuthToken != "issued-node-token" || state.Name != "collector-a" {
				t.Fatalf("unexpected state: %#v", state)
			}
			break
		}

		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("LoadState did not succeed before deadline: %v", err)
		}

		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRunLeasesUnknownJobAndReportsJobSuccess(t *testing.T) {
	t.Parallel()

	store := newCollectorMemoryNodeStore()
	store.enqueueJob(jobtypes.Record{
		ID:         "job-1",
		SiteID:     "site-1",
		Kind:       "scan",
		Capability: "unsupported",
		Status:     jobtypes.StatusQueued,
		CreatedAt:  time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC),
		UpdatedAt:  time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC),
	})

	httpServer := httptest.NewServer(store.handler())
	defer httpServer.Close()

	statePath := filepath.Join(t.TempDir(), "collector-state.json")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- Run(ctx, config.CollectorConfig{
			Name:              "collector-a",
			ServerURL:         httpServer.URL,
			SiteID:            "site-1",
			EnrollmentToken:   "bootstrap-token",
			StatePath:         statePath,
			HeartbeatInterval: 10 * time.Millisecond,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if store.jobStatus("job-1") == jobtypes.StatusSuccess {
			break
		}

		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("job status did not reach success before deadline; got %q", store.jobStatus("job-1"))
		}

		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRunLeasesDemoJobUploadsObservationBatchAndReportsSuccess(t *testing.T) {
	t.Parallel()

	store := newCollectorMemoryNodeStore()
	store.enqueueJob(jobtypes.Record{
		ID:         "job-demo-1",
		SiteID:     "site-1",
		Kind:       "demo",
		Capability: "icmp",
		Status:     jobtypes.StatusQueued,
		CreatedAt:  time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC),
		UpdatedAt:  time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC),
	})

	httpServer := httptest.NewServer(store.handler())
	defer httpServer.Close()

	statePath := filepath.Join(t.TempDir(), "collector-state.json")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- Run(ctx, config.CollectorConfig{
			Name:              "collector-a",
			ServerURL:         httpServer.URL,
			SiteID:            "site-1",
			EnrollmentToken:   "bootstrap-token",
			StatePath:         statePath,
			HeartbeatInterval: 10 * time.Millisecond,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if store.jobStatus("job-demo-1") == jobtypes.StatusSuccess && store.uploadedObservationCount() == 1 {
			break
		}

		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("demo job did not complete with upload before deadline; status=%q uploads=%d", store.jobStatus("job-demo-1"), store.uploadedObservationCount())
		}

		time.Sleep(10 * time.Millisecond)
	}

	observation := store.firstUploadedObservation(t)
	if observation.Type != "icmp.alive" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "icmp.alive")
	}

	if observation.SiteID != "site-1" {
		t.Fatalf("observation.SiteID = %q, want %q", observation.SiteID, "site-1")
	}

	if observation.JobID != "job-demo-1" {
		t.Fatalf("observation.JobID = %q, want %q", observation.JobID, "job-demo-1")
	}

	if observation.Emitter == nil || observation.Emitter.ID != "node-1" {
		t.Fatalf("observation.Emitter = %#v, want emitter with id %q", observation.Emitter, "node-1")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

type collectorMemoryNodeStore struct {
	mu               sync.Mutex
	enrollmentToken  string
	issuedToken      string
	nodeID           string
	siteID           string
	name             string
	heartbeatCount   int
	heartbeatVersion string
	jobs             map[string]jobtypes.Record
	jobOrder         []string
	uploads          []observations.Observation
}

func newCollectorMemoryNodeStore() *collectorMemoryNodeStore {
	return &collectorMemoryNodeStore{
		enrollmentToken: "bootstrap-token",
		issuedToken:     "issued-node-token",
		nodeID:          "node-1",
		siteID:          "site-1",
		jobs:            make(map[string]jobtypes.Record),
	}
}

func (s *collectorMemoryNodeStore) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/nodes/enroll", s.handleEnroll)
	mux.HandleFunc("/api/v1/nodes/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/v1/jobs/lease", s.handleLease)
	mux.HandleFunc("/api/v1/jobs/", s.handleJobStatus)
	mux.HandleFunc("/api/v1/observations/batch", s.handleObservationBatch)
	return mux
}

func (s *collectorMemoryNodeStore) enqueueJob(job jobtypes.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobs[job.ID] = job
	s.jobOrder = append(s.jobOrder, job.ID)
}

func (s *collectorMemoryNodeStore) jobStatus(jobID string) jobtypes.Status {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.jobs[jobID]
	if !ok {
		return ""
	}

	return job.Status
}

func (s *collectorMemoryNodeStore) uploadedObservationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.uploads)
}

func (s *collectorMemoryNodeStore) firstUploadedObservation(t *testing.T) observations.Observation {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.uploads) == 0 {
		t.Fatal("uploads = 0, want at least one uploaded observation")
	}

	return s.uploads[0]
}

func (s *collectorMemoryNodeStore) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") != "Bearer "+s.enrollmentToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var request nodes.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.siteID = request.SiteID
	s.name = request.Name
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(nodes.EnrollResponse{
		NodeID:    s.nodeID,
		SiteID:    request.SiteID,
		Kind:      request.Kind,
		Name:      request.Name,
		AuthToken: s.issuedToken,
	})
}

func (s *collectorMemoryNodeStore) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") != "Bearer "+s.issuedToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var request nodes.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.heartbeatCount++
	s.heartbeatVersion = strings.TrimSpace(request.Version)
	if strings.TrimSpace(request.Name) != "" {
		s.name = strings.TrimSpace(request.Name)
	}
	s.mu.Unlock()

	now := time.Date(2026, time.April, 4, 9, 20, 0, 0, time.UTC)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodes.HeartbeatResponse{
		NodeID:          s.nodeID,
		SiteID:          s.siteID,
		Kind:            nodes.KindCollector,
		Name:            s.name,
		Version:         request.Version,
		Capabilities:    request.Capabilities,
		HealthStatus:    request.HealthStatus,
		LastHeartbeatAt: now,
	})
}

func (s *collectorMemoryNodeStore) handleLease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") != "Bearer "+s.issuedToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var request jobtypes.LeaseRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, jobID := range s.jobOrder {
		job := s.jobs[jobID]
		if job.Status != jobtypes.StatusQueued {
			continue
		}

		leaseExpiresAt := time.Date(2026, time.April, 4, 9, 20, 30, 0, time.UTC)
		job.Status = jobtypes.StatusRunning
		job.NodeID = &s.nodeID
		job.LeaseOwnerNodeID = &s.nodeID
		job.LeaseExpiresAt = &leaseExpiresAt
		job.StartedAt = timePointer(time.Date(2026, time.April, 4, 9, 20, 0, 0, time.UTC))
		job.UpdatedAt = time.Date(2026, time.April, 4, 9, 20, 0, 0, time.UTC)
		s.jobs[jobID] = job

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jobtypes.LeaseResponse{Job: job})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *collectorMemoryNodeStore) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") != "Bearer "+s.issuedToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jobID := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/"), "/status"), "/")
	if jobID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var request jobtypes.StatusRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.jobs[jobID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	job.Status = request.Status
	job.LeaseOwnerNodeID = nil
	job.LeaseExpiresAt = nil
	job.CompletedAt = timePointer(time.Date(2026, time.April, 4, 9, 20, 1, 0, time.UTC))
	job.UpdatedAt = time.Date(2026, time.April, 4, 9, 20, 1, 0, time.UTC)
	s.jobs[jobID] = job

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jobtypes.StatusResponse{Job: job})
}

func (s *collectorMemoryNodeStore) handleObservationBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") != "Bearer "+s.issuedToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var request observations.BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.uploads = append(s.uploads, request.Observations...)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(observations.BatchResponse{Accepted: len(request.Observations)})
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}
