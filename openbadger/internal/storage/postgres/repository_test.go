package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNormalizeCapabilities(t *testing.T) {
	t.Parallel()

	got := normalizeCapabilities([]string{" ssh ", "SNMP", "ssh", "", "flow", "snmp"})
	want := []string{"flow", "snmp", "ssh"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeCapabilities() = %#v, want %#v", got, want)
	}
}

func TestNormalizeObservationLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 20},
		{name: "negative", limit: -1, want: 20},
		{name: "within range", limit: 15, want: 15},
		{name: "clamped", limit: 200, want: 100},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := normalizeObservationLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeObservationLimit() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNormalizeAssetLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: 100},
		{name: "negative", limit: -1, want: 100},
		{name: "within range", limit: 50, want: 50},
		{name: "clamped", limit: 1000, want: 500},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := normalizeAssetLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeAssetLimit() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCreateObservationValidation(t *testing.T) {
	t.Parallel()

	repo := NewRepository(&stubObservationDB{})
	observedAt := time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC)
	payload := json.RawMessage(`{"schema_version":"0.1"}`)

	tests := []struct {
		name   string
		params CreateObservationParams
		want   string
	}{
		{
			name: "missing site id",
			params: CreateObservationParams{
				Type:       "icmp.alive",
				Scope:      "sighting",
				ObservedAt: observedAt,
				Payload:    payload,
			},
			want: "observation site id is required",
		},
		{
			name: "missing type",
			params: CreateObservationParams{
				SiteID:     "site-1",
				Scope:      "sighting",
				ObservedAt: observedAt,
				Payload:    payload,
			},
			want: "observation type is required",
		},
		{
			name: "invalid scope",
			params: CreateObservationParams{
				SiteID:     "site-1",
				Type:       "icmp.alive",
				Scope:      "invalid",
				ObservedAt: observedAt,
				Payload:    payload,
			},
			want: `observation scope "invalid" is invalid`,
		},
		{
			name: "missing observed at",
			params: CreateObservationParams{
				SiteID:  "site-1",
				Type:    "icmp.alive",
				Scope:   "sighting",
				Payload: payload,
			},
			want: "observation observed_at is required",
		},
		{
			name: "missing payload",
			params: CreateObservationParams{
				SiteID:     "site-1",
				Type:       "icmp.alive",
				Scope:      "sighting",
				ObservedAt: observedAt,
			},
			want: "observation payload is required",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := repo.CreateObservation(context.Background(), tt.params)
			if err == nil {
				t.Fatalf("CreateObservation() error = nil, want %q", tt.want)
			}

			if err.Error() != tt.want {
				t.Fatalf("CreateObservation() error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestCreateJobValidation(t *testing.T) {
	t.Parallel()

	repo := NewRepository(&stubObservationDB{})
	_, err := repo.CreateJob(context.Background(), CreateJobParams{
		SiteID:     "site-1",
		Kind:       "scan",
		Capability: "icmp",
		Payload:    json.RawMessage(`{"targets":`),
	})
	if err == nil {
		t.Fatal("CreateJob() error = nil, want validation error")
	}

	if err.Error() != "job payload must be valid json" {
		t.Fatalf("CreateJob() error = %q, want %q", err.Error(), "job payload must be valid json")
	}
}

func TestDeleteObservationsBeforeValidation(t *testing.T) {
	t.Parallel()

	repo := NewRepository(&stubObservationDB{})
	if _, err := repo.DeleteObservationsBefore(context.Background(), time.Time{}); err == nil {
		t.Fatal("DeleteObservationsBefore() error = nil, want validation error")
	}
}

func TestDeleteObservationsBeforeExecutesDelete(t *testing.T) {
	t.Parallel()

	db := &stubExecDB{rowsAffected: 3}
	repo := NewRepository(db)
	cutoff := time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC)

	deleted, err := repo.DeleteObservationsBefore(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("DeleteObservationsBefore returned error: %v", err)
	}

	if deleted != 3 {
		t.Fatalf("DeleteObservationsBefore() = %d, want %d", deleted, 3)
	}

	if len(db.lastExecArgs) != 1 {
		t.Fatalf("len(lastExecArgs) = %d, want %d", len(db.lastExecArgs), 1)
	}

	got, ok := db.lastExecArgs[0].(time.Time)
	if !ok || !got.Equal(cutoff) {
		t.Fatalf("lastExecArgs[0] = %#v, want %v", db.lastExecArgs[0], cutoff)
	}
}

type stubObservationDB struct{}

func (s *stubObservationDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (s *stubObservationDB) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, nil
}

func (s *stubObservationDB) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return stubObservationRow{}
}

type stubObservationRow struct{}

func (r stubObservationRow) Scan(dest ...any) error {
	for _, target := range dest {
		switch value := target.(type) {
		case *time.Time:
			*value = time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC)
		}
	}

	return nil
}

type stubExecDB struct {
	stubObservationDB
	rowsAffected int64
	lastExecArgs []any
}

func (s *stubExecDB) Exec(_ context.Context, _ string, arguments ...any) (pgconn.CommandTag, error) {
	s.lastExecArgs = append([]any(nil), arguments...)
	return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", s.rowsAffected)), nil
}
