package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/mbaybarsk/openbadger/internal/config"
)

func New(cfg config.LoggingConfig, w io.Writer) (*slog.Logger, error) {
	if w == nil {
		w = io.Discard
	}

	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	handler, err := newHandler(cfg.Format, w, level)
	if err != nil {
		return nil, err
	}

	return slog.New(handler), nil
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", level)
	}
}

func newHandler(format string, w io.Writer, level slog.Level) (slog.Handler, error) {
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: redactAttr}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return slog.NewJSONHandler(w, opts), nil
	case "text":
		return slog.NewTextHandler(w, opts), nil
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}
}
