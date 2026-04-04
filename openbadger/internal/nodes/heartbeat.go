package nodes

import (
	"strings"
	"time"
)

const (
	defaultExpectedHeartbeatInterval = 30 * time.Second
	defaultStaleAfterMisses          = 3
)

func HeartbeatExpired(lastHeartbeatAt *time.Time, now time.Time, expectedInterval time.Duration, missedHeartbeats int) bool {
	if lastHeartbeatAt == nil {
		return true
	}

	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	deadline := lastHeartbeatAt.UTC().Add(normalizeExpectedHeartbeatInterval(expectedInterval) * time.Duration(normalizeMissedHeartbeats(missedHeartbeats)))
	return !deadline.After(now)
}

func EffectiveHealthStatus(current string, lastHeartbeatAt *time.Time, now time.Time, expectedInterval time.Duration, missedHeartbeats int) string {
	if HeartbeatExpired(lastHeartbeatAt, now, expectedInterval, missedHeartbeats) {
		return "stale"
	}

	current = strings.TrimSpace(current)
	if current == "" {
		return "healthy"
	}

	return current
}

func normalizeExpectedHeartbeatInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultExpectedHeartbeatInterval
	}

	return interval
}

func normalizeMissedHeartbeats(missedHeartbeats int) int {
	if missedHeartbeats <= 0 {
		return defaultStaleAfterMisses
	}

	return missedHeartbeats
}
