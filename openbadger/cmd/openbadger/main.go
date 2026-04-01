package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mbaybarsk/openbadger/internal/collector"
	"github.com/mbaybarsk/openbadger/internal/config"
	"github.com/mbaybarsk/openbadger/internal/sensor"
	"github.com/mbaybarsk/openbadger/internal/server"
	"github.com/mbaybarsk/openbadger/internal/storage/migrations"
	"github.com/mbaybarsk/openbadger/internal/version"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("Received signal, shutting down", "signal", sig)
		cancel()
	}()

	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("Application failed", "error", err)
		os.Exit(1)
	}
}

func setupLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: l,
	}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	return slog.New(handler)
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("openbadger", flag.ContinueOnError)
	versionFlag := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *versionFlag {
		fmt.Printf("OpenBadger version %s\n", version.Version)
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	logger := setupLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	parsedArgs := fs.Args()
	subcommand := cfg.Mode
	if len(parsedArgs) > 0 {
		subcommand = parsedArgs[0]
	}

	switch subcommand {
	case "server":
		srv := server.New(cfg, logger)
		return srv.Start(ctx)
	case "collector":
		return collector.Run(ctx)
	case "sensor":
		return sensor.Run(ctx)
	case "migrate":
		logger.Info("Starting migrate mode")
		if cfg.Database.URL == "" {
			return fmt.Errorf("OB_DB_URL is required for migrations")
		}
		if err := migrations.RunMigrations(cfg.Database.URL); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
		logger.Info("Migration complete")
		return nil
	default:
		return fmt.Errorf("unknown subcommand: %s", subcommand)
	}
}
