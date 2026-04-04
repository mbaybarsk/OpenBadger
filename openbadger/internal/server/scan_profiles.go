package server

import (
	"context"
	"net/http"

	"github.com/mbaybarsk/openbadger/internal/profiles"
)

type scanProfileStore interface {
	CreateScanProfile(ctx context.Context, params profiles.CreateScanProfileRequest) (profiles.ScanProfile, error)
}

type scanProfileService struct {
	store scanProfileStore
}

func newScanProfileService(store scanProfileStore) *scanProfileService {
	return &scanProfileService{store: store}
}

func (s *scanProfileService) Create(ctx context.Context, request profiles.CreateScanProfileRequest) (profiles.ScanProfile, error) {
	if s == nil || s.store == nil {
		return profiles.ScanProfile{}, errServiceUnavailable("scan profile")
	}

	return s.store.CreateScanProfile(ctx, request)
}

func debugScanProfilesHandler(service *scanProfileService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "scan profile service unavailable")
			return
		}

		var request profiles.CreateScanProfileRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		record, err := service.Create(r.Context(), request)
		if err != nil {
			writeAdminError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, profiles.DebugCreateScanProfileResponse{ScanProfile: record})
	}
}
