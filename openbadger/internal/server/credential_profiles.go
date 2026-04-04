package server

import (
	"context"
	"net/http"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	"github.com/mbaybarsk/openbadger/internal/ops"
)

type credentialProfileStore interface {
	CreateCredentialProfile(ctx context.Context, params credentials.CreateRequest) (credentials.Profile, error)
}

type credentialProfileService struct {
	store credentialProfileStore
}

func newCredentialProfileService(store credentialProfileStore) *credentialProfileService {
	return &credentialProfileService{store: store}
}

func (s *credentialProfileService) Create(ctx context.Context, request credentials.CreateRequest) (credentials.Profile, error) {
	if s == nil || s.store == nil {
		return credentials.Profile{}, errServiceUnavailable("credential profile")
	}

	record, err := s.store.CreateCredentialProfile(ctx, request)
	if err != nil {
		return credentials.Profile{}, err
	}

	ops.CredentialProfilesCreatedTotal.Add(1)

	return record.Sanitized(), nil
}

func debugCredentialProfilesHandler(service *credentialProfileService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "credential profile service unavailable")
			return
		}

		var request credentials.CreateRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		record, err := service.Create(r.Context(), request)
		if err != nil {
			writeAdminError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, credentials.DebugCreateResponse{CredentialProfile: record})
	}
}
