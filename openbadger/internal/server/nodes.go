package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/auth"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/ops"
)

var errUnauthorized = errors.New("unauthorized")

type nodeStore interface {
	CreateNode(ctx context.Context, params nodes.CreateParams) (nodes.Record, error)
	GetNodeByAuthTokenHash(ctx context.Context, tokenHash string) (nodes.Record, error)
	UpdateNodeHeartbeat(ctx context.Context, params nodes.HeartbeatParams) (nodes.Record, error)
	ListNodes(ctx context.Context) ([]nodes.Record, error)
}

type nodeService struct {
	store                      nodeStore
	bootstrapTokenHash         string
	now                        func() time.Time
	generateToken              func() (string, error)
	expectedHeartbeatInterval  time.Duration
	staleAfterMissedHeartbeats int
}

func newNodeService(store nodeStore, bootstrapToken string, now func() time.Time, generateToken func() (string, error)) *nodeService {
	if now == nil {
		now = time.Now
	}

	if generateToken == nil {
		generateToken = auth.GenerateToken
	}

	return &nodeService{
		store:                      store,
		bootstrapTokenHash:         auth.HashToken(bootstrapToken),
		now:                        now,
		generateToken:              generateToken,
		expectedHeartbeatInterval:  30 * time.Second,
		staleAfterMissedHeartbeats: 3,
	}
}

func (s *nodeService) WithHeartbeatPolicy(expectedInterval time.Duration, staleAfterMissedHeartbeats int) *nodeService {
	if s == nil {
		return nil
	}

	s.expectedHeartbeatInterval = expectedInterval
	s.staleAfterMissedHeartbeats = staleAfterMissedHeartbeats
	return s
}

func (s *nodeService) Enroll(ctx context.Context, bootstrapToken string, request nodes.EnrollRequest) (nodes.EnrollResponse, error) {
	if s == nil || s.store == nil {
		return nodes.EnrollResponse{}, fmt.Errorf("node service is unavailable")
	}

	if !auth.MatchToken(s.bootstrapTokenHash, bootstrapToken) {
		return nodes.EnrollResponse{}, errUnauthorized
	}

	siteID := strings.TrimSpace(request.SiteID)
	if siteID == "" {
		return nodes.EnrollResponse{}, fmt.Errorf("site_id is required")
	}

	kind := nodes.NormalizeKind(string(request.Kind))
	if !nodes.ValidateKind(kind) {
		return nodes.EnrollResponse{}, fmt.Errorf("kind %q is invalid", request.Kind)
	}

	name := strings.TrimSpace(request.Name)
	if name == "" {
		return nodes.EnrollResponse{}, fmt.Errorf("name is required")
	}

	token, err := s.generateToken()
	if err != nil {
		return nodes.EnrollResponse{}, fmt.Errorf("generate node token: %w", err)
	}

	record, err := s.store.CreateNode(ctx, nodes.CreateParams{
		SiteID:        siteID,
		Kind:          kind,
		Name:          name,
		Version:       strings.TrimSpace(request.Version),
		Capabilities:  nodes.NormalizeCapabilities(request.Capabilities),
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken(token),
	})
	if err != nil {
		return nodes.EnrollResponse{}, err
	}

	return nodes.EnrollResponse{
		NodeID:    record.ID,
		SiteID:    record.SiteID,
		Kind:      record.Kind,
		Name:      record.Name,
		AuthToken: token,
	}, nil
}

func (s *nodeService) Heartbeat(ctx context.Context, token string, request nodes.HeartbeatRequest) (nodes.HeartbeatResponse, error) {
	if s == nil || s.store == nil {
		return nodes.HeartbeatResponse{}, fmt.Errorf("node service is unavailable")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nodes.HeartbeatResponse{}, errUnauthorized
	}

	record, err := s.store.GetNodeByAuthTokenHash(ctx, auth.HashToken(token))
	if err != nil {
		if errors.Is(err, nodes.ErrNotFound) {
			return nodes.HeartbeatResponse{}, errUnauthorized
		}

		return nodes.HeartbeatResponse{}, err
	}

	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = record.Name
	}

	version := strings.TrimSpace(request.Version)
	if version == "" {
		version = record.Version
	}

	capabilities := nodes.NormalizeCapabilities(request.Capabilities)
	if len(capabilities) == 0 {
		capabilities = record.Capabilities
	}

	healthStatus := strings.TrimSpace(request.HealthStatus)
	if healthStatus == "" {
		healthStatus = "healthy"
	}

	updated, err := s.store.UpdateNodeHeartbeat(ctx, nodes.HeartbeatParams{
		NodeID:          record.ID,
		Name:            name,
		Version:         version,
		Capabilities:    capabilities,
		HealthStatus:    healthStatus,
		LastHeartbeatAt: s.now().UTC(),
	})
	if err != nil {
		return nodes.HeartbeatResponse{}, err
	}

	ops.NodeHeartbeatsTotal.Add(1)

	response := nodes.HeartbeatResponse{
		NodeID:       updated.ID,
		SiteID:       updated.SiteID,
		Kind:         updated.Kind,
		Name:         updated.Name,
		Version:      updated.Version,
		Capabilities: updated.Capabilities,
		HealthStatus: updated.HealthStatus,
	}

	if updated.LastHeartbeatAt != nil {
		response.LastHeartbeatAt = updated.LastHeartbeatAt.UTC()
	}

	return response, nil
}

func (s *nodeService) ListNodes(ctx context.Context) ([]nodes.DebugRecord, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("node service is unavailable")
	}

	records, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]nodes.DebugRecord, 0, len(records))
	now := s.now().UTC()
	for _, record := range records {
		stale := nodes.HeartbeatExpired(record.LastHeartbeatAt, now, s.expectedHeartbeatInterval, s.staleAfterMissedHeartbeats)
		result = append(result, nodes.DebugRecord{
			NodeID:          record.ID,
			SiteID:          record.SiteID,
			Kind:            record.Kind,
			Name:            record.Name,
			Version:         record.Version,
			Capabilities:    record.Capabilities,
			HealthStatus:    nodes.EffectiveHealthStatus(record.HealthStatus, record.LastHeartbeatAt, now, s.expectedHeartbeatInterval, s.staleAfterMissedHeartbeats),
			Stale:           stale,
			LastHeartbeatAt: record.LastHeartbeatAt,
			CreatedAt:       record.CreatedAt,
			UpdatedAt:       record.UpdatedAt,
		})
	}

	return result, nil
}

func nodeEnrollHandler(service *nodeService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "node service unavailable")
			return
		}

		token, err := auth.BearerToken(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var request nodes.EnrollRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		response, err := service.Enroll(r.Context(), token, request)
		if err != nil {
			writeNodeError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, response)
	}
}

func nodeHeartbeatHandler(service *nodeService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "node service unavailable")
			return
		}

		token, err := auth.BearerToken(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var request nodes.HeartbeatRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		response, err := service.Heartbeat(r.Context(), token, request)
		if err != nil {
			writeNodeError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, response)
	}
}

func debugNodesHandler(service *nodeService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "node service unavailable")
			return
		}

		records, err := service.ListNodes(r.Context())
		if err != nil {
			writeNodeError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"nodes": records})
	}
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeNodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, nodes.ErrConflict):
		writeJSONError(w, http.StatusConflict, err.Error())
	case isValidationError(err):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
	}
}

func isValidationError(err error) bool {
	if err == nil {
		return false
	}

	message := err.Error()
	return strings.Contains(message, "required") || strings.Contains(message, "invalid")
}
