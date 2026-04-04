package icmp

import (
	"net/netip"
	"testing"
	"time"
)

func TestNormalizeAliveObservation(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.April, 4, 12, 0, 1, 400_000_000, time.UTC)
	observation, err := NormalizeAliveObservation(NormalizeRequest{
		SiteID:      "site-1",
		JobID:       "job-1",
		NodeKind:    "collector",
		NodeID:      "node-1",
		NodeName:    "collector-a",
		Version:     "0.1.0",
		TargetInput: "192.0.2.1",
		IP:          netip.MustParseAddr("192.0.2.1"),
		ObservedAt:  observedAt,
		RTT:         1500 * time.Microsecond,
		TTL:         64,
	})
	if err != nil {
		t.Fatalf("NormalizeAliveObservation returned error: %v", err)
	}

	if observation.Type != "icmp.alive" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "icmp.alive")
	}

	if observation.Scope != "sighting" {
		t.Fatalf("observation.Scope = %q, want %q", observation.Scope, "sighting")
	}

	if observation.Target == nil || observation.Target.IP != "192.0.2.1" || observation.Target.Protocol != "icmp" {
		t.Fatalf("observation.Target = %#v, want icmp target 192.0.2.1", observation.Target)
	}

	if observation.Addresses == nil || len(observation.Addresses.IPAddresses) != 1 || observation.Addresses.IPAddresses[0] != "192.0.2.1" {
		t.Fatalf("observation.Addresses = %#v, want one normalized IP", observation.Addresses)
	}

	if got, ok := observation.Facts["rtt_ms"].(float64); !ok || got != 1.5 {
		t.Fatalf("observation.Facts[rtt_ms] = %#v, want %v", observation.Facts["rtt_ms"], 1.5)
	}

	if got, ok := observation.Facts["ttl"].(int); !ok || got != 64 {
		t.Fatalf("observation.Facts[ttl] = %#v, want %d", observation.Facts["ttl"], 64)
	}

	if observation.Evidence == nil || observation.Evidence.SourceProtocol != "icmp" || observation.Evidence.Confidence != 0.6 {
		t.Fatalf("observation.Evidence = %#v, want icmp confidence 0.6", observation.Evidence)
	}

	if !observation.ObservedAt.Equal(time.Date(2026, time.April, 4, 12, 0, 1, 0, time.UTC)) {
		t.Fatalf("observation.ObservedAt = %s, want truncated second", observation.ObservedAt)
	}
}

func TestNormalizeAliveObservationValidation(t *testing.T) {
	t.Parallel()

	_, err := NormalizeAliveObservation(NormalizeRequest{})
	if err == nil {
		t.Fatal("NormalizeAliveObservation() error = nil, want validation error")
	}

	if err.Error() != "icmp observation site id is required" {
		t.Fatalf("NormalizeAliveObservation() error = %q, want %q", err.Error(), "icmp observation site id is required")
	}
}
