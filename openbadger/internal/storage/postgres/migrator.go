package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mbaybarsk/openbadger/migrations"
)

const createSchemaMigrationsTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version TEXT PRIMARY KEY,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

func ApplyMigrations(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("nil postgres pool")
	}

	if logger == nil {
		logger = slog.Default()
	}

	filenames, err := migrationFiles(migrations.Files)
	if err != nil {
		return 0, fmt.Errorf("list migrations: %w", err)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin migration transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err := tx.Exec(ctx, createSchemaMigrationsTableSQL); err != nil {
		return 0, fmt.Errorf("create schema migrations table: %w", err)
	}

	applied, err := appliedVersions(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("load applied migrations: %w", err)
	}

	appliedCount := 0
	for _, filename := range filenames {
		if applied[filename] {
			continue
		}

		body, err := fs.ReadFile(migrations.Files, filename)
		if err != nil {
			return 0, fmt.Errorf("read migration %q: %w", filename, err)
		}

		sql := strings.TrimSpace(string(body))
		if sql == "" {
			return 0, fmt.Errorf("migration %q is empty", filename)
		}

		if _, err := tx.Exec(ctx, sql); err != nil {
			return 0, fmt.Errorf("apply migration %q: %w", filename, err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, filename); err != nil {
			return 0, fmt.Errorf("record migration %q: %w", filename, err)
		}

		appliedCount++
		logger.Info("applied migration", "version", filename)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit migration transaction: %w", err)
	}

	committed = true
	return appliedCount, nil
}

func migrationFiles(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}

	filenames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		filenames = append(filenames, entry.Name())
	}

	slices.Sort(filenames)
	return filenames, nil
}

type versionQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func appliedVersions(ctx context.Context, db versionQueryer) (map[string]bool, error) {
	rows, err := db.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}

		versions[version] = true
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return versions, nil
}
