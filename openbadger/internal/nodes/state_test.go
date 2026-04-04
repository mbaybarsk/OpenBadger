package nodes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadStateRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "collector-state.json")
	want := State{
		NodeID:    "node-123",
		SiteID:    "site-123",
		Kind:      KindCollector,
		Name:      "collector-a",
		AuthToken: "node-token",
	}

	if err := SaveState(path, want); err != nil {
		t.Fatalf("SaveState returned error: %v", err)
	}

	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState returned error: %v", err)
	}

	if got != want {
		t.Fatalf("state = %#v, want %#v", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat returned error: %v", err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o, want %o", info.Mode().Perm(), 0o600)
	}
}

func TestSaveStateOverwritesExistingState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "sensor-state.json")

	if err := SaveState(path, State{
		NodeID:    "node-1",
		SiteID:    "site-1",
		Kind:      KindSensor,
		Name:      "sensor-a",
		AuthToken: "token-a",
	}); err != nil {
		t.Fatalf("SaveState returned error: %v", err)
	}

	if err := SaveState(path, State{
		NodeID:    "node-1",
		SiteID:    "site-1",
		Kind:      KindSensor,
		Name:      "sensor-b",
		AuthToken: "token-b",
	}); err != nil {
		t.Fatalf("SaveState returned error: %v", err)
	}

	state, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState returned error: %v", err)
	}

	if state.Name != "sensor-b" {
		t.Fatalf("state.Name = %q, want %q", state.Name, "sensor-b")
	}

	if state.AuthToken != "token-b" {
		t.Fatalf("state.AuthToken = %q, want %q", state.AuthToken, "token-b")
	}
}
