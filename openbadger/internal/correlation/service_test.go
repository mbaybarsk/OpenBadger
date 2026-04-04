package correlation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/observations"
)

func TestServiceCorrelateScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T, service *Service, store *memoryStore)
	}{
		{
			name: "merge on strong identifier",
			run: func(t *testing.T, service *Service, store *memoryStore) {
				ctx := context.Background()
				first := mustObservation(t, "site-1", "obs-1", time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC), func(o *observations.Observation) {
					o.Type = "ssh.host"
					o.Scope = "asset"
					o.Identifiers = &observations.Identifiers{SerialNumber: "SER-001", Hostnames: []string{"web-01"}}
					o.Addresses = &observations.Addresses{IPAddresses: []string{"192.0.2.10"}}
				})

				second := mustObservation(t, "site-1", "obs-2", time.Date(2026, time.April, 4, 12, 5, 0, 0, time.UTC), func(o *observations.Observation) {
					o.Type = "winrm.windows_host"
					o.Scope = "asset"
					o.Identifiers = &observations.Identifiers{SerialNumber: "SER-001", Hostnames: []string{"web-01"}}
					o.Addresses = &observations.Addresses{IPAddresses: []string{"192.0.2.20"}}
				})

				if _, err := service.Correlate(ctx, first); err != nil {
					t.Fatalf("Correlate(first) returned error: %v", err)
				}
				if _, err := service.Correlate(ctx, second); err != nil {
					t.Fatalf("Correlate(second) returned error: %v", err)
				}

				if got := len(store.assets); got != 1 {
					t.Fatalf("len(store.assets) = %d, want %d", got, 1)
				}

				asset := store.onlyAsset(t)
				if asset.Provisional {
					t.Fatal("asset.Provisional = true, want false")
				}

				if got := store.identifierValues(asset.ID, IdentifierKindSerialNumber); len(got) != 1 || got[0] != "ser-001" {
					t.Fatalf("serial identifiers = %#v, want [ser-001]", got)
				}

				if got := store.addressValues(asset.ID, AddressTypeIP); fmt.Sprintf("%v", got) != "[192.0.2.10 192.0.2.20]" {
					t.Fatalf("ip addresses = %v, want [192.0.2.10 192.0.2.20]", got)
				}

				if got := len(store.sightings); got != 2 {
					t.Fatalf("len(store.sightings) = %d, want %d", got, 2)
				}
			},
		},
		{
			name: "no merge on conflicting strong identifiers",
			run: func(t *testing.T, service *Service, store *memoryStore) {
				ctx := context.Background()
				first := mustObservation(t, "site-1", "obs-1", time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC), func(o *observations.Observation) {
					o.Type = "ssh.host"
					o.Scope = "asset"
					o.Identifiers = &observations.Identifiers{SerialNumber: "SER-001"}
					o.Addresses = &observations.Addresses{IPAddresses: []string{"192.0.2.10"}}
				})

				second := mustObservation(t, "site-1", "obs-2", time.Date(2026, time.April, 4, 12, 2, 0, 0, time.UTC), func(o *observations.Observation) {
					o.Type = "winrm.windows_host"
					o.Scope = "asset"
					o.Identifiers = &observations.Identifiers{SerialNumber: "SER-002"}
					o.Addresses = &observations.Addresses{IPAddresses: []string{"192.0.2.10"}}
				})

				if _, err := service.Correlate(ctx, first); err != nil {
					t.Fatalf("Correlate(first) returned error: %v", err)
				}
				if _, err := service.Correlate(ctx, second); err != nil {
					t.Fatalf("Correlate(second) returned error: %v", err)
				}

				if got := len(store.assets); got != 2 {
					t.Fatalf("len(store.assets) = %d, want %d", got, 2)
				}

				serials := store.allIdentifierValues(IdentifierKindSerialNumber)
				if fmt.Sprintf("%v", serials) != "[ser-001 ser-002]" {
					t.Fatalf("serial identifiers = %v, want [ser-001 ser-002]", serials)
				}
			},
		},
		{
			name: "provisional asset from weak evidence",
			run: func(t *testing.T, service *Service, store *memoryStore) {
				ctx := context.Background()
				observation := mustObservation(t, "site-1", "obs-1", time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC), func(o *observations.Observation) {
					o.Type = "icmp.alive"
					o.Scope = "sighting"
					o.Addresses = &observations.Addresses{IPAddresses: []string{"192.0.2.40"}}
					if o.Identifiers != nil {
						o.Identifiers = nil
					}
				})

				if _, err := service.Correlate(ctx, observation); err != nil {
					t.Fatalf("Correlate() returned error: %v", err)
				}

				if got := len(store.assets); got != 1 {
					t.Fatalf("len(store.assets) = %d, want %d", got, 1)
				}

				asset := store.onlyAsset(t)
				if !asset.Provisional {
					t.Fatal("asset.Provisional = false, want true")
				}

				if got := store.addressValues(asset.ID, AddressTypeIP); fmt.Sprintf("%v", got) != "[192.0.2.40]" {
					t.Fatalf("ip addresses = %v, want [192.0.2.40]", got)
				}
			},
		},
		{
			name: "later merge of provisional asset when stronger evidence appears",
			run: func(t *testing.T, service *Service, store *memoryStore) {
				ctx := context.Background()
				weak := mustObservation(t, "site-1", "obs-1", time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC), func(o *observations.Observation) {
					o.Type = "icmp.alive"
					o.Scope = "sighting"
					o.Addresses = &observations.Addresses{IPAddresses: []string{"198.51.100.10"}}
					if o.Identifiers != nil {
						o.Identifiers = nil
					}
				})

				strong := mustObservation(t, "site-1", "obs-2", time.Date(2026, time.April, 4, 12, 10, 0, 0, time.UTC), func(o *observations.Observation) {
					o.Type = "ssh.host"
					o.Scope = "asset"
					o.Identifiers = &observations.Identifiers{SerialNumber: "SER-100", Hostnames: []string{"app-01"}}
					o.Addresses = &observations.Addresses{IPAddresses: []string{"198.51.100.10"}}
				})

				if _, err := service.Correlate(ctx, weak); err != nil {
					t.Fatalf("Correlate(weak) returned error: %v", err)
				}
				if _, err := service.Correlate(ctx, strong); err != nil {
					t.Fatalf("Correlate(strong) returned error: %v", err)
				}

				if got := len(store.assets); got != 1 {
					t.Fatalf("len(store.assets) = %d, want %d", got, 1)
				}

				asset := store.onlyAsset(t)
				if asset.Provisional {
					t.Fatal("asset.Provisional = true, want false")
				}

				if got := store.identifierValues(asset.ID, IdentifierKindSerialNumber); len(got) != 1 || got[0] != "ser-100" {
					t.Fatalf("serial identifiers = %#v, want [ser-100]", got)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newMemoryStore()
			service := NewService(store)
			tt.run(t, service, store)
		})
	}
}

type memoryStore struct {
	nextID      int
	assets      map[string]Asset
	identifiers map[string][]IdentifierRecord
	addresses   map[string][]AddressRecord
	sightings   []Sighting
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		assets:      make(map[string]Asset),
		identifiers: make(map[string][]IdentifierRecord),
		addresses:   make(map[string][]AddressRecord),
	}
}

func (s *memoryStore) FindAssetsByIdentifiers(_ context.Context, siteID string, identifiers []Identifier) ([]AssetSnapshot, error) {
	if len(identifiers) == 0 {
		return nil, nil
	}

	matched := make(map[string]AssetSnapshot)
	for _, identifier := range identifiers {
		for assetID, records := range s.identifiers {
			asset := s.assets[assetID]
			if asset.SiteID != strings.TrimSpace(siteID) {
				continue
			}

			for _, record := range records {
				if record.Kind == identifier.Kind && record.Value == identifier.Value {
					matched[assetID] = s.snapshot(assetID)
					break
				}
			}
		}
	}

	return orderedSnapshots(matched), nil
}

func (s *memoryStore) FindAssetsByAddresses(_ context.Context, siteID string, addresses []Address) ([]AssetSnapshot, error) {
	if len(addresses) == 0 {
		return nil, nil
	}

	matched := make(map[string]AssetSnapshot)
	for _, address := range addresses {
		for assetID, records := range s.addresses {
			asset := s.assets[assetID]
			if asset.SiteID != strings.TrimSpace(siteID) {
				continue
			}

			for _, record := range records {
				if record.Type == address.Type && record.Value == address.Value {
					matched[assetID] = s.snapshot(assetID)
					break
				}
			}
		}
	}

	return orderedSnapshots(matched), nil
}

func (s *memoryStore) CreateAsset(_ context.Context, params CreateAssetParams) (Asset, error) {
	s.nextID++
	asset := Asset{
		ID:          fmt.Sprintf("asset-%d", s.nextID),
		SiteID:      params.SiteID,
		Provisional: params.Provisional,
		FirstSeen:   params.FirstSeen.UTC(),
		LastSeen:    params.LastSeen.UTC(),
		CreatedAt:   params.LastSeen.UTC(),
		UpdatedAt:   params.LastSeen.UTC(),
	}
	s.assets[asset.ID] = asset
	return asset, nil
}

func (s *memoryStore) UpdateAsset(_ context.Context, params UpdateAssetParams) (Asset, error) {
	asset := s.assets[params.AssetID]
	asset.Provisional = params.Provisional
	if asset.FirstSeen.IsZero() || params.FirstSeen.Before(asset.FirstSeen) {
		asset.FirstSeen = params.FirstSeen.UTC()
	}
	if params.LastSeen.After(asset.LastSeen) {
		asset.LastSeen = params.LastSeen.UTC()
	}
	asset.UpdatedAt = params.LastSeen.UTC()
	s.assets[asset.ID] = asset
	return asset, nil
}

func (s *memoryStore) UpsertAssetIdentifiers(_ context.Context, params UpsertAssetIdentifiersParams) error {
	records := s.identifiers[params.AssetID]
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

		records = append(records, IdentifierRecord{
			AssetID:   params.AssetID,
			Kind:      identifier.Kind,
			Value:     identifier.Value,
			FirstSeen: params.FirstSeen.UTC(),
			LastSeen:  params.LastSeen.UTC(),
		})
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}

		return records[i].Value < records[j].Value
	})

	s.identifiers[params.AssetID] = records
	return nil
}

func (s *memoryStore) UpsertAssetAddresses(_ context.Context, params UpsertAssetAddressesParams) error {
	records := s.addresses[params.AssetID]
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

		records = append(records, AddressRecord{
			AssetID:   params.AssetID,
			Type:      address.Type,
			Value:     address.Value,
			FirstSeen: params.FirstSeen.UTC(),
			LastSeen:  params.LastSeen.UTC(),
		})
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}

		return records[i].Value < records[j].Value
	})

	s.addresses[params.AssetID] = records
	return nil
}

func (s *memoryStore) CreateSighting(_ context.Context, params CreateSightingParams) error {
	s.sightings = append(s.sightings, Sighting{
		ID:               fmt.Sprintf("sighting-%d", len(s.sightings)+1),
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
	})
	return nil
}

func (s *memoryStore) onlyAsset(t *testing.T) Asset {
	t.Helper()
	if len(s.assets) != 1 {
		t.Fatalf("len(s.assets) = %d, want %d", len(s.assets), 1)
	}

	for _, asset := range s.assets {
		return asset
	}

	t.Fatal("assets map is empty")
	return Asset{}
}

func (s *memoryStore) identifierValues(assetID string, kind string) []string {
	values := make([]string, 0)
	for _, record := range s.identifiers[assetID] {
		if record.Kind == kind {
			values = append(values, record.Value)
		}
	}
	return values
}

func (s *memoryStore) addressValues(assetID string, addressType string) []string {
	values := make([]string, 0)
	for _, record := range s.addresses[assetID] {
		if record.Type == addressType {
			values = append(values, record.Value)
		}
	}
	return values
}

func (s *memoryStore) allIdentifierValues(kind string) []string {
	values := make([]string, 0)
	for assetID := range s.assets {
		values = append(values, s.identifierValues(assetID, kind)...)
	}
	sort.Strings(values)
	return values
}

func (s *memoryStore) snapshot(assetID string) AssetSnapshot {
	return AssetSnapshot{
		Asset:       s.assets[assetID],
		Identifiers: append([]IdentifierRecord(nil), s.identifiers[assetID]...),
		Addresses:   append([]AddressRecord(nil), s.addresses[assetID]...),
	}
}

func orderedSnapshots(values map[string]AssetSnapshot) []AssetSnapshot {
	ordered := make([]AssetSnapshot, 0, len(values))
	for _, value := range values {
		ordered = append(ordered, value)
	}

	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Asset.ID < ordered[j].Asset.ID
	})

	return ordered
}

func mustObservation(t *testing.T, siteID string, observationID string, observedAt time.Time, mutate func(*observations.Observation)) observations.Observation {
	t.Helper()

	observation := observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: observationID,
		Type:          "icmp.alive",
		Scope:         "sighting",
		SiteID:        siteID,
		Emitter:       &observations.Emitter{Kind: "collector", ID: "node-1"},
		ObservedAt:    observedAt,
		Facts:         map[string]any{"ok": true},
		Evidence:      &observations.Evidence{Confidence: 0.8, SourceProtocol: "test"},
		Addresses:     &observations.Addresses{},
		Identifiers:   &observations.Identifiers{},
	}

	if mutate != nil {
		mutate(&observation)
	}

	if err := observation.Validate(); err != nil {
		t.Fatalf("observation.Validate() returned error: %v", err)
	}

	return observation
}
