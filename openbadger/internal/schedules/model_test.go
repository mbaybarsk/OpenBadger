package schedules

import (
	"testing"
	"time"
)

func TestParseExpression(t *testing.T) {
	t.Parallel()

	if _, err := ParseExpression("*/15 * * * *"); err != nil {
		t.Fatalf("ParseExpression returned error: %v", err)
	}
}

func TestParseExpressionInvalid(t *testing.T) {
	t.Parallel()

	_, err := ParseExpression("not-a-cron")
	if err == nil {
		t.Fatal("ParseExpression returned nil error, want invalid expression error")
	}
}

func TestNextRun(t *testing.T) {
	t.Parallel()

	nextRun, err := NextRun("*/5 * * * *", time.Date(2026, time.April, 4, 12, 3, 10, 0, time.UTC))
	if err != nil {
		t.Fatalf("NextRun returned error: %v", err)
	}

	want := time.Date(2026, time.April, 4, 12, 5, 0, 0, time.UTC)
	if !nextRun.Equal(want) {
		t.Fatalf("nextRun = %s, want %s", nextRun, want)
	}
}

func TestNextRunFromExactBoundaryMovesForward(t *testing.T) {
	t.Parallel()

	nextRun, err := NextRun("0 * * * *", time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NextRun returned error: %v", err)
	}

	want := time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC)
	if !nextRun.Equal(want) {
		t.Fatalf("nextRun = %s, want %s", nextRun, want)
	}
}
