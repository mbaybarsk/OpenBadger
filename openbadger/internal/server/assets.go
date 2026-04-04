package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
)

type assetStore interface {
	ListAssets(ctx context.Context, params postgres.ListAssetsParams) ([]postgres.AssetListItem, error)
	GetAssetDetail(ctx context.Context, assetID string) (postgres.AssetDetail, error)
}

type assetService struct {
	store assetStore
}

func newAssetService(store assetStore) *assetService {
	return &assetService{store: store}
}

func (s *assetService) List(ctx context.Context, siteID string, limit int) ([]postgres.AssetListItem, error) {
	if s == nil || s.store == nil {
		return nil, errServiceUnavailable("asset")
	}

	return s.store.ListAssets(ctx, postgres.ListAssetsParams{SiteID: strings.TrimSpace(siteID), Limit: limit})
}

func (s *assetService) Detail(ctx context.Context, assetID string) (postgres.AssetDetail, error) {
	if s == nil || s.store == nil {
		return postgres.AssetDetail{}, errServiceUnavailable("asset")
	}

	return s.store.GetAssetDetail(ctx, assetID)
}

func (s *assetService) ExportCSV(ctx context.Context, siteID string, limit int) ([]byte, error) {
	assets, err := s.List(ctx, siteID, limit)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)

	rows := [][]string{{
		"asset_id",
		"site_id",
		"provisional",
		"hostnames",
		"fqdn",
		"serial_number",
		"system_uuid",
		"bios_uuid",
		"snmp_engine_id",
		"ssh_host_key_fingerprints",
		"mac_addresses",
		"ip_addresses",
		"first_seen",
		"last_seen",
	}}

	for _, asset := range assets {
		rows = append(rows, []string{
			asset.Asset.ID,
			asset.Asset.SiteID,
			strconv.FormatBool(asset.Asset.Provisional),
			strings.Join(asset.Hostnames, ";"),
			asset.FQDN,
			asset.SerialNumber,
			asset.SystemUUID,
			asset.BIOSUUID,
			asset.SNMPEngineID,
			strings.Join(asset.SSHHostKeyFingerprints, ";"),
			strings.Join(asset.MACAddresses, ";"),
			strings.Join(asset.IPAddresses, ";"),
			asset.Asset.FirstSeen.UTC().Format(timeFormatRFC3339),
			asset.Asset.LastSeen.UTC().Format(timeFormatRFC3339),
		})
	}

	if err := writer.WriteAll(rows); err != nil {
		return nil, fmt.Errorf("write assets csv: %w", err)
	}

	return buffer.Bytes(), nil
}

const timeFormatRFC3339 = "2006-01-02T15:04:05Z07:00"

func assetsHandler(service *assetService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "asset service unavailable")
			return
		}

		limit, err := assetLimit(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		assets, err := service.List(r.Context(), r.URL.Query().Get("site_id"), limit)
		if err != nil {
			writeAssetError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"assets": assets})
	}
}

func assetDetailHandler(service *assetService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "asset service unavailable")
			return
		}

		assetID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/assets/"))
		if assetID == "" || strings.Contains(assetID, "/") {
			writeJSONError(w, http.StatusNotFound, "not found")
			return
		}

		detail, err := service.Detail(r.Context(), assetID)
		if err != nil {
			writeAssetError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, detail)
	}
}

func assetsCSVHandler(service *assetService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "asset service unavailable")
			return
		}

		limit, err := assetLimit(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		body, err := service.ExportCSV(r.Context(), r.URL.Query().Get("site_id"), limit)
		if err != nil {
			writeAssetError(w, err)
			return
		}

		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

func writeAssetError(w http.ResponseWriter, err error) {
	var unavailable serviceUnavailableError
	switch {
	case errors.As(err, &unavailable):
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, postgres.ErrAssetNotFound):
		writeJSONError(w, http.StatusNotFound, err.Error())
	case isValidationError(err):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
	}
}

func assetLimit(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return 100, nil
	}

	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("limit is invalid")
	}

	if limit > 500 {
		limit = 500
	}

	return limit, nil
}
