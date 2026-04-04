package logging

import (
	"io"
	"testing"

	"github.com/mbaybarsk/openbadger/internal/config"
)

func TestNewReturnsLogger(t *testing.T) {
	t.Parallel()

	logger, err := New(config.LoggingConfig{Level: "debug", Format: "json"}, io.Discard)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if logger == nil {
		t.Fatal("logger is nil")
	}
}

func TestNewRejectsUnsupportedFormat(t *testing.T) {
	t.Parallel()

	_, err := New(config.LoggingConfig{Level: "info", Format: "yaml"}, io.Discard)
	if err == nil {
		t.Fatal("New returned nil error, want error")
	}
}
