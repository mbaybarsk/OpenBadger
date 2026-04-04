package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mbaybarsk/openbadger/internal/collector"
	"github.com/mbaybarsk/openbadger/internal/config"
	"github.com/mbaybarsk/openbadger/internal/logging"
	"github.com/mbaybarsk/openbadger/internal/sensor"
	"github.com/mbaybarsk/openbadger/internal/server"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
	"github.com/mbaybarsk/openbadger/internal/version"
)

const (
	modeServer    = "server"
	modeCollector = "collector"
	modeSensor    = "sensor"
	modeMigrate   = "migrate"
)

type command struct {
	mode        string
	showUsage   bool
	showVersion bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cmd, err := parseArgs(args)
	if err != nil {
		return err
	}

	if cmd.showUsage {
		_, err := fmt.Fprintln(stdout, usage())
		return err
	}

	if cmd.showVersion {
		_, err := fmt.Fprintf(stdout, "%s %s\n", version.Name, version.Version)
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := cfg.Validate(cmd.mode); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	logger, err := logging.New(cfg.Log, stderr)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}

	logger = logger.With("service", version.Name, "version", version.Version, "mode", cmd.mode)
	slog.SetDefault(logger)

	switch cmd.mode {
	case modeServer:
		return server.Run(ctx, cfg.Server, cfg.Database, logger)
	case modeCollector:
		return collector.Run(ctx, cfg.Collector, logger)
	case modeSensor:
		return sensor.Run(ctx, cfg.Sensor, logger)
	case modeMigrate:
		return runMigrate(ctx, cfg.Database, logger)
	default:
		return fmt.Errorf("unsupported mode %q", cmd.mode)
	}
}

func parseArgs(args []string) (command, error) {
	fs := flag.NewFlagSet(version.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return command{showUsage: true}, nil
		}

		return command{}, fmt.Errorf("%w\n\n%s", err, usage())
	}

	if *showVersion {
		return command{showVersion: true}, nil
	}

	if fs.NArg() != 1 {
		return command{}, fmt.Errorf("expected exactly one mode\n\n%s", usage())
	}

	mode := strings.ToLower(fs.Arg(0))

	switch mode {
	case modeServer, modeCollector, modeSensor, modeMigrate:
		return command{mode: mode}, nil
	default:
		return command{}, fmt.Errorf("unknown mode %q\n\n%s", mode, usage())
	}
}

func runMigrate(ctx context.Context, cfg config.DatabaseConfig, logger *slog.Logger) error {
	logger.Info("starting mode", "database_configured", cfg.URL != "")

	db, err := postgres.Open(ctx, cfg.URL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	applied, err := postgres.ApplyMigrations(ctx, db, logger)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	logger.Info("migrate completed", "applied", applied)
	return nil
}

func usage() string {
	return `Usage: openbadger [--version] <mode>

Modes:
  server     start the central server runtime
  collector  start the active collection runtime
  sensor     start the passive sensor runtime
  migrate    run database migrations`
}
