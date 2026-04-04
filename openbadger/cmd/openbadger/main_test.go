package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestParseArgsAcceptsKnownMode(t *testing.T) {
	t.Parallel()

	cmd, err := parseArgs([]string{"server"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if cmd.mode != modeServer {
		t.Fatalf("mode = %q, want %q", cmd.mode, modeServer)
	}
}

func TestParseArgsAcceptsMigrateMode(t *testing.T) {
	t.Parallel()

	cmd, err := parseArgs([]string{"migrate"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if cmd.mode != modeMigrate {
		t.Fatalf("mode = %q, want %q", cmd.mode, modeMigrate)
	}
}

func TestParseArgsSupportsVersionFlag(t *testing.T) {
	t.Parallel()

	cmd, err := parseArgs([]string{"--version"})
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}

	if !cmd.showVersion {
		t.Fatal("showVersion = false, want true")
	}
}

func TestParseArgsRejectsUnknownMode(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{"unknown"})
	if err == nil {
		t.Fatal("parseArgs returned nil error, want error")
	}

	if !strings.Contains(err.Error(), "unknown mode") {
		t.Fatalf("error = %q, want to contain %q", err.Error(), "unknown mode")
	}
}

func TestRunPrintsVersion(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(context.Background(), []string{"--version"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if got := stdout.String(); !strings.Contains(got, "openbadger dev") {
		t.Fatalf("stdout = %q, want version output", got)
	}

	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}
