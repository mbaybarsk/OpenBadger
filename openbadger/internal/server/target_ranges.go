package server

import (
	"context"
	"net/http"

	"github.com/mbaybarsk/openbadger/internal/targets"
)

type targetRangeStore interface {
	CreateTargetRange(ctx context.Context, params targets.CreateRequest) (targets.Record, error)
}

type targetRangeService struct {
	store targetRangeStore
}

func newTargetRangeService(store targetRangeStore) *targetRangeService {
	return &targetRangeService{store: store}
}

func (s *targetRangeService) Create(ctx context.Context, request targets.CreateRequest) (targets.Record, error) {
	if s == nil || s.store == nil {
		return targets.Record{}, errServiceUnavailable("target range")
	}

	return s.store.CreateTargetRange(ctx, request)
}

func debugTargetRangesHandler(service *targetRangeService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "target range service unavailable")
			return
		}

		var request targets.CreateRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		record, err := service.Create(r.Context(), request)
		if err != nil {
			writeAdminError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, targets.DebugCreateResponse{TargetRange: record})
	}
}
