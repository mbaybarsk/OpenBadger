package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/correlation"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
)

func TestAssetsHandlerReturnsList(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	assetID := seedAsset(t, store)
	handler := newHandler(HandlerOptions{AssetService: newAssetService(store)})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets?site_id=site-1", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response struct {
		Assets []postgres.AssetListItem `json:"assets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if len(response.Assets) != 1 {
		t.Fatalf("len(response.Assets) = %d, want %d", len(response.Assets), 1)
	}

	if response.Assets[0].Asset.ID != assetID {
		t.Fatalf("response.Assets[0].Asset.ID = %q, want %q", response.Assets[0].Asset.ID, assetID)
	}

	if response.Assets[0].SerialNumber != "ser-1" {
		t.Fatalf("response.Assets[0].SerialNumber = %q, want %q", response.Assets[0].SerialNumber, "ser-1")
	}
}

func TestAssetDetailHandlerReturnsAsset(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	assetID := seedAsset(t, store)
	handler := newHandler(HandlerOptions{AssetService: newAssetService(store)})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/"+assetID, nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var detail postgres.AssetDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if detail.Asset.ID != assetID {
		t.Fatalf("detail.Asset.ID = %q, want %q", detail.Asset.ID, assetID)
	}

	if len(detail.Identifiers) == 0 {
		t.Fatal("len(detail.Identifiers) = 0, want at least one identifier")
	}

	if len(detail.Sightings) != 1 {
		t.Fatalf("len(detail.Sightings) = %d, want %d", len(detail.Sightings), 1)
	}
}

func TestAssetsCSVHandlerReturnsExpectedShape(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	seedAsset(t, store)
	handler := newHandler(HandlerOptions{AssetService: newAssetService(store)})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets.csv?site_id=site-1", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if got := rec.Header().Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Fatalf("content-type = %q, want %q", got, "text/csv; charset=utf-8")
	}

	reader := csv.NewReader(strings.NewReader(rec.Body.String()))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want %d", len(records), 2)
	}

	headers := []string{"asset_id", "site_id", "provisional", "hostnames", "fqdn", "serial_number", "system_uuid", "bios_uuid", "snmp_engine_id", "ssh_host_key_fingerprints", "mac_addresses", "ip_addresses", "first_seen", "last_seen"}
	if fmt.Sprintf("%v", records[0]) != fmt.Sprintf("%v", headers) {
		t.Fatalf("headers = %v, want %v", records[0], headers)
	}

	if len(records[1]) != len(headers) {
		t.Fatalf("len(records[1]) = %d, want %d", len(records[1]), len(headers))
	}

	if records[1][5] != "ser-1" {
		t.Fatalf("serial_number column = %q, want %q", records[1][5], "ser-1")
	}
}

func (s *memoryNodeStore) ListAssets(_ context.Context, params postgres.ListAssetsParams) ([]postgres.AssetListItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	items := make([]postgres.AssetListItem, 0, len(s.assetsByID))
	for _, asset := range s.assetsByID {
		if siteID := strings.TrimSpace(params.SiteID); siteID != "" && asset.SiteID != siteID {
			continue
		}

		item := postgres.AssetListItem{Asset: asset}
		for _, identifier := range s.assetIdentifiersByAsset[asset.ID] {
			switch identifier.Kind {
			case correlation.IdentifierKindHostname:
				item.Hostnames = append(item.Hostnames, identifier.Value)
			case correlation.IdentifierKindFQDN:
				if item.FQDN == "" {
					item.FQDN = identifier.Value
				}
			case correlation.IdentifierKindSerialNumber:
				if item.SerialNumber == "" {
					item.SerialNumber = identifier.Value
				}
			case correlation.IdentifierKindSystemUUID:
				if item.SystemUUID == "" {
					item.SystemUUID = identifier.Value
				}
			case correlation.IdentifierKindBIOSUUID:
				if item.BIOSUUID == "" {
					item.BIOSUUID = identifier.Value
				}
			case correlation.IdentifierKindSNMPEngineID:
				if item.SNMPEngineID == "" {
					item.SNMPEngineID = identifier.Value
				}
			case correlation.IdentifierKindSSHHostKeyFingerprint:
				item.SSHHostKeyFingerprints = append(item.SSHHostKeyFingerprints, identifier.Value)
			}
		}

		for _, address := range s.assetAddressesByAsset[asset.ID] {
			switch address.Type {
			case correlation.AddressTypeMAC:
				item.MACAddresses = append(item.MACAddresses, address.Value)
			case correlation.AddressTypeIP:
				item.IPAddresses = append(item.IPAddresses, address.Value)
			}
		}

		items = append(items, item)
	}

	return items, nil
}

func (s *memoryNodeStore) GetAssetDetail(_ context.Context, assetID string) (postgres.AssetDetail, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	assetID = strings.TrimSpace(assetID)
	asset, ok := s.assetsByID[assetID]
	if !ok {
		return postgres.AssetDetail{}, postgres.ErrAssetNotFound
	}

	return postgres.AssetDetail{
		Asset:       asset,
		Identifiers: append([]postgres.AssetIdentifier(nil), s.assetIdentifiersByAsset[assetID]...),
		Addresses:   append([]postgres.AssetAddress(nil), s.assetAddressesByAsset[assetID]...),
		Sightings:   append([]postgres.Sighting(nil), s.sightingsByAsset[assetID]...),
	}, nil
}

func (s *memoryNodeStore) FindAssetsByIdentifiers(_ context.Context, siteID string, identifiers []correlation.Identifier) ([]correlation.AssetSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	matched := make(map[string]correlation.AssetSnapshot)
	for _, identifier := range identifiers {
		for assetID, records := range s.assetIdentifiersByAsset {
			asset := s.assetsByID[assetID]
			if strings.TrimSpace(siteID) != "" && asset.SiteID != strings.TrimSpace(siteID) {
				continue
			}

			for _, record := range records {
				if record.Kind == identifier.Kind && record.Value == identifier.Value {
					matched[assetID] = correlation.AssetSnapshot{
						Asset:       asset,
						Identifiers: append([]correlation.IdentifierRecord(nil), s.assetIdentifiersByAsset[assetID]...),
						Addresses:   append([]correlation.AddressRecord(nil), s.assetAddressesByAsset[assetID]...),
					}
					break
				}
			}
		}
	}

	return orderedAssetSnapshots(matched), nil
}

func (s *memoryNodeStore) FindAssetsByAddresses(_ context.Context, siteID string, addresses []correlation.Address) ([]correlation.AssetSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	matched := make(map[string]correlation.AssetSnapshot)
	for _, address := range addresses {
		for assetID, records := range s.assetAddressesByAsset {
			asset := s.assetsByID[assetID]
			if strings.TrimSpace(siteID) != "" && asset.SiteID != strings.TrimSpace(siteID) {
				continue
			}

			for _, record := range records {
				if record.Type == address.Type && record.Value == address.Value {
					matched[assetID] = correlation.AssetSnapshot{
						Asset:       asset,
						Identifiers: append([]correlation.IdentifierRecord(nil), s.assetIdentifiersByAsset[assetID]...),
						Addresses:   append([]correlation.AddressRecord(nil), s.assetAddressesByAsset[assetID]...),
					}
					break
				}
			}
		}
	}

	return orderedAssetSnapshots(matched), nil
}

func (s *memoryNodeStore) CreateAsset(_ context.Context, params correlation.CreateAssetParams) (correlation.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.assetSequence++
	asset := correlation.Asset{
		ID:          fmt.Sprintf("asset-%d", s.assetSequence),
		SiteID:      strings.TrimSpace(params.SiteID),
		Provisional: params.Provisional,
		FirstSeen:   params.FirstSeen.UTC(),
		LastSeen:    params.LastSeen.UTC(),
		CreatedAt:   params.LastSeen.UTC(),
		UpdatedAt:   params.LastSeen.UTC(),
	}

	s.assetsByID[asset.ID] = asset
	return asset, nil
}

func (s *memoryNodeStore) UpdateAsset(_ context.Context, params correlation.UpdateAssetParams) (correlation.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	asset, ok := s.assetsByID[strings.TrimSpace(params.AssetID)]
	if !ok {
		return correlation.Asset{}, postgres.ErrAssetNotFound
	}

	asset.Provisional = params.Provisional
	if asset.FirstSeen.IsZero() || params.FirstSeen.Before(asset.FirstSeen) {
		asset.FirstSeen = params.FirstSeen.UTC()
	}
	if params.LastSeen.After(asset.LastSeen) {
		asset.LastSeen = params.LastSeen.UTC()
	}
	asset.UpdatedAt = params.LastSeen.UTC()
	s.assetsByID[asset.ID] = asset

	return asset, nil
}

func (s *memoryNodeStore) UpsertAssetIdentifiers(_ context.Context, params correlation.UpsertAssetIdentifiersParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	records := s.assetIdentifiersByAsset[params.AssetID]
	for _, identifier := range params.Identifiers {
		updated := false
		for i := range records {
			if records[i].Kind == identifier.Kind && records[i].Value == identifier.Value {
				if params.FirstSeen.Before(records[i].FirstSeen) {
					records[i].FirstSeen = params.FirstSeen.UTC()
				}
				if params.LastSeen.After(records[i].LastSeen) {
					records[i].LastSeen = params.LastSeen.UTC()
				}
				updated = true
				break
			}
		}

		if updated {
			continue
		}

		records = append(records, postgres.AssetIdentifier{
			AssetID:   params.AssetID,
			Kind:      identifier.Kind,
			Value:     identifier.Value,
			FirstSeen: params.FirstSeen.UTC(),
			LastSeen:  params.LastSeen.UTC(),
		})
	}

	s.assetIdentifiersByAsset[params.AssetID] = records
	return nil
}

func (s *memoryNodeStore) UpsertAssetAddresses(_ context.Context, params correlation.UpsertAssetAddressesParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	records := s.assetAddressesByAsset[params.AssetID]
	for _, address := range params.Addresses {
		updated := false
		for i := range records {
			if records[i].Type == address.Type && records[i].Value == address.Value {
				if params.FirstSeen.Before(records[i].FirstSeen) {
					records[i].FirstSeen = params.FirstSeen.UTC()
				}
				if params.LastSeen.After(records[i].LastSeen) {
					records[i].LastSeen = params.LastSeen.UTC()
				}
				updated = true
				break
			}
		}

		if updated {
			continue
		}

		records = append(records, postgres.AssetAddress{
			AssetID:   params.AssetID,
			Type:      address.Type,
			Value:     address.Value,
			FirstSeen: params.FirstSeen.UTC(),
			LastSeen:  params.LastSeen.UTC(),
		})
	}

	s.assetAddressesByAsset[params.AssetID] = records
	return nil
}

func (s *memoryNodeStore) CreateSighting(_ context.Context, params correlation.CreateSightingParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sighting := postgres.Sighting{
		ID:               fmt.Sprintf("sighting-%d", len(s.sightingsByAsset[params.AssetID])+1),
		AssetID:          params.AssetID,
		SiteID:           params.SiteID,
		ObservationID:    params.ObservationID,
		ObservationType:  params.ObservationType,
		ObservationScope: params.ObservationScope,
		JobID:            params.JobID,
		NodeID:           params.NodeID,
		ObservedAt:       params.ObservedAt.UTC(),
		FirstSeen:        params.FirstSeen,
		LastSeen:         params.LastSeen,
		Confidence:       params.Confidence,
		SourceProtocol:   params.SourceProtocol,
		CreatedAt:        params.ObservedAt.UTC(),
	}

	s.sightingsByAsset[params.AssetID] = append(s.sightingsByAsset[params.AssetID], sighting)
	return nil
}

func orderedAssetSnapshots(values map[string]correlation.AssetSnapshot) []correlation.AssetSnapshot {
	ordered := make([]correlation.AssetSnapshot, 0, len(values))
	for _, value := range values {
		ordered = append(ordered, value)
	}

	return ordered
}

func seedAsset(t *testing.T, store *memoryNodeStore) string {
	t.Helper()

	ctx := context.Background()
	observedAt := time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC)
	asset, err := store.CreateAsset(ctx, correlation.CreateAssetParams{
		SiteID:      "site-1",
		Provisional: false,
		FirstSeen:   observedAt,
		LastSeen:    observedAt,
	})
	if err != nil {
		t.Fatalf("CreateAsset returned error: %v", err)
	}

	if err := store.UpsertAssetIdentifiers(ctx, correlation.UpsertAssetIdentifiersParams{
		AssetID:       asset.ID,
		SiteID:        asset.SiteID,
		ObservationID: "obs-1",
		FirstSeen:     observedAt,
		LastSeen:      observedAt,
		Identifiers: []correlation.Identifier{
			{Kind: correlation.IdentifierKindHostname, Value: "host-1"},
			{Kind: correlation.IdentifierKindSerialNumber, Value: "ser-1"},
		},
	}); err != nil {
		t.Fatalf("UpsertAssetIdentifiers returned error: %v", err)
	}

	if err := store.UpsertAssetAddresses(ctx, correlation.UpsertAssetAddressesParams{
		AssetID:       asset.ID,
		SiteID:        asset.SiteID,
		ObservationID: "obs-1",
		FirstSeen:     observedAt,
		LastSeen:      observedAt,
		Addresses: []correlation.Address{
			{Type: correlation.AddressTypeIP, Value: "192.0.2.10"},
			{Type: correlation.AddressTypeMAC, Value: "aa:bb:cc:dd:ee:ff"},
		},
	}); err != nil {
		t.Fatalf("UpsertAssetAddresses returned error: %v", err)
	}

	if err := store.CreateSighting(ctx, correlation.CreateSightingParams{
		AssetID:          asset.ID,
		SiteID:           asset.SiteID,
		ObservationID:    "obs-1",
		ObservationType:  "ssh.host",
		ObservationScope: "asset",
		ObservedAt:       observedAt,
		Confidence:       0.9,
		SourceProtocol:   "ssh",
	}); err != nil {
		t.Fatalf("CreateSighting returned error: %v", err)
	}

	return asset.ID
}
