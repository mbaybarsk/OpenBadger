package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mbaybarsk/openbadger/internal/auth"
	"github.com/mbaybarsk/openbadger/internal/credentials"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

func TestSchedulerRunOnceCreatesJobIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openServerIntegrationPool(t, ctx)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := postgres.NewRepository(tx)
	site, err := repo.CreateSite(ctx, postgres.CreateSiteParams{Slug: "site-server-scheduler", Name: "Server Scheduler Site"})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	if _, err := repo.CreateNode(ctx, postgres.CreateNodeParams{
		SiteID:        site.ID,
		Kind:          postgres.NodeKindCollector,
		Name:          "collector-server-scheduler",
		Version:       "0.1.0",
		Capabilities:  []string{"icmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("token-hash"),
	}); err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	targetRange, err := repo.CreateTargetRange(ctx, targets.CreateRequest{
		SiteID: site.ID,
		Name:   "branch-a",
		CIDR:   "192.0.2.0/24",
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := repo.CreateScanProfile(ctx, profiles.CreateScanProfileRequest{
		SiteID:      site.ID,
		Name:        "icmp-default",
		Capability:  "icmp",
		TimeoutMS:   1000,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	enabled := true
	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	if _, err := repo.CreateSchedule(ctx, postgres.CreateScheduleParams{
		SiteID:         site.ID,
		Name:           "every-minute",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(repo, func() time.Time { return now })
	created, err := scheduler.RunOnce(ctx, nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	var count int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE site_id = $1 AND capability = 'icmp'`, site.ID).Scan(&count); err != nil {
		t.Fatalf("QueryRow returned error: %v", err)
	}

	if count != 1 {
		t.Fatalf("job count = %d, want %d", count, 1)
	}
}

func TestSchedulerRunOnceCreatesSNMPJobIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openServerIntegrationPool(t, ctx)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := postgres.NewRepository(tx)
	site, err := repo.CreateSite(ctx, postgres.CreateSiteParams{Slug: "site-server-scheduler-snmp", Name: "Server Scheduler SNMP Site"})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	if _, err := repo.CreateNode(ctx, postgres.CreateNodeParams{
		SiteID:        site.ID,
		Kind:          postgres.NodeKindCollector,
		Name:          "collector-server-scheduler-snmp",
		Version:       "0.1.0",
		Capabilities:  []string{"snmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("token-hash-snmp"),
	}); err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	credentialProfile, err := repo.CreateCredentialProfile(ctx, credentials.CreateRequest{
		SiteID:   site.ID,
		Name:     "snmp-v2c-default",
		Protocol: credentials.ProtocolSNMP,
		SNMP: &credentials.SNMPProfile{
			Version:   credentials.SNMPVersion2c,
			Community: "public",
		},
	})
	if err != nil {
		t.Fatalf("CreateCredentialProfile returned error: %v", err)
	}

	targetRange, err := repo.CreateTargetRange(ctx, targets.CreateRequest{
		SiteID: site.ID,
		Name:   "branch-a",
		CIDR:   "192.0.2.0/24",
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := repo.CreateScanProfile(ctx, profiles.CreateScanProfileRequest{
		SiteID:              site.ID,
		Name:                "snmp-default",
		Capability:          "snmp",
		TimeoutMS:           2000,
		RetryCount:          1,
		Concurrency:         2,
		CredentialProfileID: &credentialProfile.ID,
	})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	enabled := true
	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	if _, err := repo.CreateSchedule(ctx, postgres.CreateScheduleParams{
		SiteID:         site.ID,
		Name:           "every-minute-snmp",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(repo, func() time.Time { return now })
	created, err := scheduler.RunOnce(ctx, nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	var rawPayload []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM jobs WHERE site_id = $1 AND capability = 'snmp' LIMIT 1`, site.ID).Scan(&rawPayload); err != nil {
		t.Fatalf("QueryRow returned error: %v", err)
	}

	payload, err := jobtypes.ParseSNMPScanPayload(json.RawMessage(rawPayload))
	if err != nil {
		t.Fatalf("ParseSNMPScanPayload returned error: %v", err)
	}

	if payload.CredentialReference() != credentialProfile.Name {
		t.Fatalf("payload.CredentialReference() = %q, want %q", payload.CredentialReference(), credentialProfile.Name)
	}
}

func TestSchedulerRunOnceCreatesSSHJobIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openServerIntegrationPool(t, ctx)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := postgres.NewRepository(tx)
	site, err := repo.CreateSite(ctx, postgres.CreateSiteParams{Slug: "site-server-scheduler-ssh", Name: "Server Scheduler SSH Site"})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	if _, err := repo.CreateNode(ctx, postgres.CreateNodeParams{
		SiteID:        site.ID,
		Kind:          postgres.NodeKindCollector,
		Name:          "collector-server-scheduler-ssh",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("token-hash-ssh"),
	}); err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	credentialProfile, err := repo.CreateCredentialProfile(ctx, credentials.CreateRequest{
		SiteID:   site.ID,
		Name:     "linux-ssh-default",
		Protocol: credentials.ProtocolSSH,
		SSH: &credentials.SSHProfile{
			Username: "observer",
			Password: "secret-password",
		},
	})
	if err != nil {
		t.Fatalf("CreateCredentialProfile returned error: %v", err)
	}

	targetRange, err := repo.CreateTargetRange(ctx, targets.CreateRequest{
		SiteID: site.ID,
		Name:   "branch-a",
		CIDR:   "192.0.2.0/24",
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := repo.CreateScanProfile(ctx, profiles.CreateScanProfileRequest{
		SiteID:              site.ID,
		Name:                "ssh-default",
		Capability:          "ssh",
		TimeoutMS:           5000,
		RetryCount:          0,
		Concurrency:         2,
		CredentialProfileID: &credentialProfile.ID,
	})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	enabled := true
	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	if _, err := repo.CreateSchedule(ctx, postgres.CreateScheduleParams{
		SiteID:         site.ID,
		Name:           "every-minute-ssh",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(repo, func() time.Time { return now })
	created, err := scheduler.RunOnce(ctx, nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	var rawPayload []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM jobs WHERE site_id = $1 AND capability = 'ssh' LIMIT 1`, site.ID).Scan(&rawPayload); err != nil {
		t.Fatalf("QueryRow returned error: %v", err)
	}

	payload, err := jobtypes.ParseSSHScanPayload(json.RawMessage(rawPayload))
	if err != nil {
		t.Fatalf("ParseSSHScanPayload returned error: %v", err)
	}

	if payload.CredentialReference() != credentialProfile.Name {
		t.Fatalf("payload.CredentialReference() = %q, want %q", payload.CredentialReference(), credentialProfile.Name)
	}
}

func TestSchedulerRunOnceCreatesWinRMJobIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := openServerIntegrationPool(t, ctx)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin returned error: %v", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	repo := postgres.NewRepository(tx)
	site, err := repo.CreateSite(ctx, postgres.CreateSiteParams{Slug: "site-server-scheduler-winrm", Name: "Server Scheduler WinRM Site"})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	if _, err := repo.CreateNode(ctx, postgres.CreateNodeParams{
		SiteID:        site.ID,
		Kind:          postgres.NodeKindCollector,
		Name:          "collector-server-scheduler-winrm",
		Version:       "0.1.0",
		Capabilities:  []string{"winrm"},
		HealthStatus:  "healthy",
		AuthTokenHash: auth.HashToken("token-hash-winrm"),
	}); err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	credentialProfile, err := repo.CreateCredentialProfile(ctx, credentials.CreateRequest{
		SiteID:   site.ID,
		Name:     "windows-winrm-default",
		Protocol: credentials.ProtocolWinRM,
		WinRM: &credentials.WinRMProfile{
			Username: "administrator",
			Password: "secret-password",
		},
	})
	if err != nil {
		t.Fatalf("CreateCredentialProfile returned error: %v", err)
	}

	targetRange, err := repo.CreateTargetRange(ctx, targets.CreateRequest{
		SiteID: site.ID,
		Name:   "branch-a",
		CIDR:   "192.0.2.0/24",
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := repo.CreateScanProfile(ctx, profiles.CreateScanProfileRequest{
		SiteID:              site.ID,
		Name:                "winrm-default",
		Capability:          "winrm",
		TimeoutMS:           5000,
		RetryCount:          0,
		Concurrency:         2,
		CredentialProfileID: &credentialProfile.ID,
	})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	enabled := true
	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	if _, err := repo.CreateSchedule(ctx, postgres.CreateScheduleParams{
		SiteID:         site.ID,
		Name:           "every-minute-winrm",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(repo, func() time.Time { return now })
	created, err := scheduler.RunOnce(ctx, nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	var rawPayload []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM jobs WHERE site_id = $1 AND capability = 'winrm' LIMIT 1`, site.ID).Scan(&rawPayload); err != nil {
		t.Fatalf("QueryRow returned error: %v", err)
	}

	payload, err := jobtypes.ParseWinRMScanPayload(json.RawMessage(rawPayload))
	if err != nil {
		t.Fatalf("ParseWinRMScanPayload returned error: %v", err)
	}

	if payload.CredentialReference() != credentialProfile.Name {
		t.Fatalf("payload.CredentialReference() = %q, want %q", payload.CredentialReference(), credentialProfile.Name)
	}
}

func openServerIntegrationPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set TEST_DB_DSN to run PostgreSQL integration tests")
	}

	pool, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := postgres.ApplyMigrations(ctx, pool, logger); err != nil {
		pool.Close()
		t.Fatalf("ApplyMigrations returned error: %v", err)
	}

	t.Cleanup(pool.Close)
	return pool
}
