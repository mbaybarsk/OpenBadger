package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/auth"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
)

type jobStore interface {
	CreateJob(ctx context.Context, params postgres.CreateJobParams) (jobtypes.Record, error)
	LeaseJob(ctx context.Context, params postgres.LeaseJobParams) (jobtypes.Record, error)
	UpdateJobStatus(ctx context.Context, params postgres.UpdateJobStatusParams) (jobtypes.Record, error)
	ListJobs(ctx context.Context, limit int) ([]jobtypes.Record, error)
	GetNodeByAuthTokenHash(ctx context.Context, tokenHash string) (nodes.Record, error)
}

type jobService struct {
	store jobStore
	now   func() time.Time
}

func newJobService(store jobStore, now func() time.Time) *jobService {
	if now == nil {
		now = time.Now
	}

	return &jobService{store: store, now: now}
}

func (s *jobService) Lease(ctx context.Context, token string, request jobtypes.LeaseRequest) (jobtypes.Record, bool, error) {
	if s == nil || s.store == nil {
		return jobtypes.Record{}, false, fmt.Errorf("job service is unavailable")
	}

	record, err := s.authenticateCollector(ctx, token)
	if err != nil {
		return jobtypes.Record{}, false, err
	}

	if request.LeaseDurationSeconds < 0 {
		return jobtypes.Record{}, false, fmt.Errorf("lease_duration_seconds is invalid")
	}

	leaseDuration := 30 * time.Second
	if request.LeaseDurationSeconds > 0 {
		leaseDuration = time.Duration(request.LeaseDurationSeconds) * time.Second
	}

	job, err := s.store.LeaseJob(ctx, postgres.LeaseJobParams{
		SiteID:        record.SiteID,
		NodeID:        record.ID,
		Capabilities:  record.Capabilities,
		LeaseDuration: leaseDuration,
		Now:           s.now().UTC(),
	})
	if err != nil {
		if errors.Is(err, jobtypes.ErrLeaseUnavailable) {
			return jobtypes.Record{}, false, nil
		}

		return jobtypes.Record{}, false, err
	}

	return job, true, nil
}

func (s *jobService) UpdateStatus(ctx context.Context, token string, jobID string, request jobtypes.StatusRequest) (jobtypes.Record, error) {
	if s == nil || s.store == nil {
		return jobtypes.Record{}, fmt.Errorf("job service is unavailable")
	}

	record, err := s.authenticateCollector(ctx, token)
	if err != nil {
		return jobtypes.Record{}, err
	}

	return s.store.UpdateJobStatus(ctx, postgres.UpdateJobStatusParams{
		JobID:        strings.TrimSpace(jobID),
		NodeID:       record.ID,
		Status:       request.Status,
		ErrorSummary: request.ErrorSummary,
		Now:          s.now().UTC(),
	})
}

func (s *jobService) CreateDebugJob(ctx context.Context, request jobtypes.DebugCreateRequest) (jobtypes.Record, error) {
	if s == nil || s.store == nil {
		return jobtypes.Record{}, fmt.Errorf("job service is unavailable")
	}

	kind := strings.TrimSpace(request.Kind)
	if kind == "" {
		kind = "scan"
	}

	return s.store.CreateJob(ctx, postgres.CreateJobParams{
		SiteID:     strings.TrimSpace(request.SiteID),
		Kind:       kind,
		Capability: strings.ToLower(strings.TrimSpace(request.Capability)),
		Payload:    append([]byte(nil), request.Payload...),
		Status:     jobtypes.StatusQueued,
	})
}

func (s *jobService) List(ctx context.Context, limit int) ([]jobtypes.Record, error) {
	if s == nil || s.store == nil {
		return nil, errServiceUnavailable("job")
	}

	return s.store.ListJobs(ctx, limit)
}

func (s *jobService) authenticateCollector(ctx context.Context, token string) (nodes.Record, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nodes.Record{}, errUnauthorized
	}

	record, err := s.store.GetNodeByAuthTokenHash(ctx, auth.HashToken(token))
	if err != nil {
		if errors.Is(err, nodes.ErrNotFound) {
			return nodes.Record{}, errUnauthorized
		}

		return nodes.Record{}, err
	}

	if record.Kind != nodes.KindCollector {
		return nodes.Record{}, errUnauthorized
	}

	return record, nil
}

func jobLeaseHandler(service *jobService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "job service unavailable")
			return
		}

		token, err := auth.BearerToken(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var request jobtypes.LeaseRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		job, leased, err := service.Lease(r.Context(), token, request)
		if err != nil {
			writeJobError(w, err)
			return
		}

		if !leased {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		writeJSON(w, http.StatusOK, jobtypes.LeaseResponse{Job: job})
	}
}

func jobStatusHandler(service *jobService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		jobID, ok := jobIDFromStatusPath(r.URL.Path)
		if !ok {
			writeJSONError(w, http.StatusNotFound, "not found")
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "job service unavailable")
			return
		}

		token, err := auth.BearerToken(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var request jobtypes.StatusRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		job, err := service.UpdateStatus(r.Context(), token, jobID, request)
		if err != nil {
			writeJobError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, jobtypes.StatusResponse{Job: job})
	}
}

func debugJobsHandler(service *jobService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "job service unavailable")
			return
		}

		var request jobtypes.DebugCreateRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		job, err := service.CreateDebugJob(r.Context(), request)
		if err != nil {
			writeJobError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, jobtypes.DebugCreateResponse{Job: job})
	}
}

func writeJobError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, jobtypes.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, jobtypes.ErrLeaseUnavailable), errors.Is(err, jobtypes.ErrLeaseOwnerMismatch), errors.Is(err, jobtypes.ErrInvalidTransition):
		writeJSONError(w, http.StatusConflict, err.Error())
	case isValidationError(err):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
	}
}

func jobIDFromStatusPath(path string) (string, bool) {
	const prefix = "/api/v1/jobs/"
	const suffix = "/status"

	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}

	jobID := strings.TrimSpace(strings.Trim(strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix), "/"))
	if jobID == "" || strings.Contains(jobID, "/") {
		return "", false
	}

	return jobID, true
}
