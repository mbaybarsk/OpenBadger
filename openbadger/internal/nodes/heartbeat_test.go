package nodes

import (
	"testing"
	"time"
)

func TestHeartbeatExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-70 * time.Second)
	stale := now.Add(-95 * time.Second)

	if HeartbeatExpired(&fresh, now, 30*time.Second, 3) {
		t.Fatal("HeartbeatExpired(fresh) = true, want false")
	}

	if !HeartbeatExpired(&stale, now, 30*time.Second, 3) {
		t.Fatal("HeartbeatExpired(stale) = false, want true")
	}
}

func TestHeartbeatExpiredWithoutHeartbeatIsStale(t *testing.T) {
	t.Parallel()

	if !HeartbeatExpired(nil, time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC), 30*time.Second, 3) {
		t.Fatal("HeartbeatExpired(nil) = false, want true")
	}
}

func TestEffectiveHealthStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-15 * time.Second)
	if got := EffectiveHealthStatus("healthy", &fresh, now, 30*time.Second, 3); got != "healthy" {
		t.Fatalf("EffectiveHealthStatus(fresh) = %q, want %q", got, "healthy")
	}

	stale := now.Add(-2 * time.Minute)
	if got := EffectiveHealthStatus("healthy", &stale, now, 30*time.Second, 3); got != "stale" {
		t.Fatalf("EffectiveHealthStatus(stale) = %q, want %q", got, "stale")
	}
}
