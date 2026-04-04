package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mbaybarsk/openbadger/internal/auth"
	"github.com/mbaybarsk/openbadger/internal/correlation"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
	"github.com/mbaybarsk/openbadger/internal/ops"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
)

type observationStore interface {
	CreateObservation(ctx context.Context, params postgres.CreateObservationParams) (postgres.Observation, error)
	ListRecentObservations(ctx context.Context, limit int) ([]postgres.Observation, error)
	GetNodeByAuthTokenHash(ctx context.Context, tokenHash string) (nodes.Record, error)
}

type observationService struct {
	store      observationStore
	correlator *correlation.Service
}

func newObservationService(store observationStore) *observationService {
	service := &observationService{store: store}
	if correlatorStore, ok := any(store).(correlation.Store); ok {
		service.correlator = correlation.NewService(correlatorStore)
	}

	return service
}

func (s *observationService) IngestBatch(ctx context.Context, token string, request observations.BatchRequest) (observations.BatchResponse, error) {
	if s == nil || s.store == nil {
		return observations.BatchResponse{}, fmt.Errorf("observation service is unavailable")
	}

	node, err := s.authenticateNode(ctx, token)
	if err != nil {
		return observations.BatchResponse{}, err
	}

	if err := request.Validate(); err != nil {
		return observations.BatchResponse{}, err
	}

	for _, observation := range request.Observations {
		if strings.TrimSpace(observation.SiteID) != node.SiteID {
			return observations.BatchResponse{}, fmt.Errorf("observation site_id is invalid")
		}

		payload, err := json.Marshal(observation)
		if err != nil {
			return observations.BatchResponse{}, fmt.Errorf("marshal observation payload: %w", err)
		}

		if _, err := s.store.CreateObservation(ctx, postgres.CreateObservationParams{
			ID:         observation.ObservationID,
			SiteID:     observation.SiteID,
			JobID:      optionalStringPointer(observation.JobID),
			NodeID:     optionalStringPointer(node.ID),
			Type:       observation.Type,
			Scope:      observation.Scope,
			ObservedAt: observation.ObservedAt,
			Payload:    payload,
		}); err != nil {
			return observations.BatchResponse{}, err
		}

		if s.correlator != nil {
			if _, err := s.correlator.Correlate(ctx, observation); err != nil {
				return observations.BatchResponse{}, err
			}
		}
	}

	ops.ObservationBatchesTotal.Add(1)
	ops.ObservationsAcceptedTotal.Add(int64(len(request.Observations)))

	return observations.BatchResponse{Accepted: len(request.Observations)}, nil
}

func (s *observationService) ListRecent(ctx context.Context, limit int) ([]postgres.Observation, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("observation service is unavailable")
	}

	return s.store.ListRecentObservations(ctx, limit)
}

func (s *observationService) authenticateNode(ctx context.Context, token string) (nodes.Record, error) {
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

	if !nodes.ValidateKind(record.Kind) {
		return nodes.Record{}, errUnauthorized
	}

	return record, nil
}

func observationBatchHandler(service *observationService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "observation service unavailable")
			return
		}

		token, err := auth.BearerToken(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var request observations.BatchRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		response, err := service.IngestBatch(r.Context(), token, request)
		if err != nil {
			writeObservationError(w, err)
			return
		}

		writeJSON(w, http.StatusAccepted, response)
	}
}

func debugObservationsHandler(service *observationService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "observation service unavailable")
			return
		}

		limit, err := observationLimit(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		records, err := service.ListRecent(r.Context(), limit)
		if err != nil {
			writeObservationError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"observations": records})
	}
}

func writeObservationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
	case isValidationError(err):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
	}
}

func observationLimit(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return 20, nil
	}

	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("limit is invalid")
	}

	if limit > 100 {
		limit = 100
	}

	return limit, nil
}

func optionalStringPointer(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}
