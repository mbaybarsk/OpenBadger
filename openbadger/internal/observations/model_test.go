package observations

import (
	"testing"
	"time"
)

func TestObservationValidate(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		observation Observation
		wantErr     string
	}{
		{
			name: "valid observation",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "sighting",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Facts:         map[string]any{"rtt_ms": 1.2},
				Evidence:      &Evidence{Confidence: 0.9, SourceProtocol: "icmp"},
			},
		},
		{
			name: "missing schema version",
			observation: Observation{
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "sighting",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Facts:         map[string]any{},
				Evidence:      &Evidence{},
			},
			wantErr: "observation schema_version is invalid",
		},
		{
			name: "missing observation id",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				Type:          "icmp.alive",
				Scope:         "sighting",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Facts:         map[string]any{},
				Evidence:      &Evidence{},
			},
			wantErr: "observation observation_id is required",
		},
		{
			name: "missing type",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Scope:         "sighting",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Facts:         map[string]any{},
				Evidence:      &Evidence{},
			},
			wantErr: "observation type is required",
		},
		{
			name: "invalid scope",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "invalid",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Facts:         map[string]any{},
				Evidence:      &Evidence{},
			},
			wantErr: "observation scope is invalid",
		},
		{
			name: "missing site id",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "sighting",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Facts:         map[string]any{},
				Evidence:      &Evidence{},
			},
			wantErr: "observation site_id is required",
		},
		{
			name: "missing emitter",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "sighting",
				SiteID:        "site-1",
				ObservedAt:    observedAt,
				Facts:         map[string]any{},
				Evidence:      &Evidence{},
			},
			wantErr: "observation emitter is required",
		},
		{
			name: "missing observed at",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "sighting",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				Facts:         map[string]any{},
				Evidence:      &Evidence{},
			},
			wantErr: "observation observed_at is required",
		},
		{
			name: "missing facts",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "sighting",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Evidence:      &Evidence{},
			},
			wantErr: "observation facts is required",
		},
		{
			name: "missing evidence",
			observation: Observation{
				SchemaVersion: SchemaVersion,
				ObservationID: "obs-1",
				Type:          "icmp.alive",
				Scope:         "sighting",
				SiteID:        "site-1",
				Emitter:       &Emitter{Kind: "collector"},
				ObservedAt:    observedAt,
				Facts:         map[string]any{},
			},
			wantErr: "observation evidence is required",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.observation.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() returned error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", tt.wantErr)
			}

			if err.Error() != tt.wantErr {
				t.Fatalf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBatchRequestValidate(t *testing.T) {
	t.Parallel()

	err := (BatchRequest{}).Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}

	if err.Error() != "observations are required" {
		t.Fatalf("Validate() error = %q, want %q", err.Error(), "observations are required")
	}
}
