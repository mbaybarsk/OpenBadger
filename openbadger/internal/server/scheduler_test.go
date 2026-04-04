package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

func TestSchedulerRunOnceCreatesJobsForDueSchedules(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	targetRange, err := store.CreateTargetRange(context.Background(), targets.CreateRequest{
		SiteID:     "site-1",
		Name:       "branch-a",
		CIDR:       "192.0.2.0/24",
		Exclusions: []string{"192.0.2.10"},
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := store.CreateScanProfile(context.Background(), profiles.CreateScanProfileRequest{
		SiteID:      "site-1",
		Name:        "icmp-default",
		Capability:  "icmp",
		TimeoutMS:   1500,
		RetryCount:  1,
		Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	enabled := true
	now := time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC)
	if _, err := store.CreateSchedule(context.Background(), schedules.CreateRequest{
		SiteID:         "site-1",
		Name:           "every-minute",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(store, func() time.Time { return now })
	created, err := scheduler.RunOnce(context.Background(), nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	job, ok := store.firstJobByCapability("icmp")
	if !ok {
		t.Fatal("firstJobByCapability returned false, want created icmp job")
	}

	var payload struct {
		Targets []struct {
			CIDR       string   `json:"cidr"`
			Exclusions []string `json:"exclusions"`
		} `json:"targets"`
		TimeoutMS int `json:"timeout_ms"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if len(payload.Targets) != 1 || payload.Targets[0].CIDR != "192.0.2.0/24" {
		t.Fatalf("payload.Targets = %#v, want one icmp target range", payload.Targets)
	}

	if payload.TimeoutMS != 1500 {
		t.Fatalf("payload.TimeoutMS = %d, want %d", payload.TimeoutMS, 1500)
	}
}

func TestSchedulerRunOnceCreatesSNMPJobsForDueSchedules(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	credentialProfile, err := store.CreateCredentialProfile(context.Background(), credentials.CreateRequest{
		SiteID:   "site-1",
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

	targetRange, err := store.CreateTargetRange(context.Background(), targets.CreateRequest{
		SiteID:     "site-1",
		Name:       "branch-a",
		CIDR:       "192.0.2.0/24",
		Exclusions: []string{"192.0.2.10"},
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := store.CreateScanProfile(context.Background(), profiles.CreateScanProfileRequest{
		SiteID:              "site-1",
		Name:                "snmp-default",
		Capability:          "snmp",
		TimeoutMS:           2500,
		RetryCount:          1,
		Concurrency:         2,
		CredentialProfileID: &credentialProfile.ID,
	})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	enabled := true
	now := time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC)
	if _, err := store.CreateSchedule(context.Background(), schedules.CreateRequest{
		SiteID:         "site-1",
		Name:           "every-minute-snmp",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(store, func() time.Time { return now })
	created, err := scheduler.RunOnce(context.Background(), nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	job, ok := store.firstJobByCapability("snmp")
	if !ok {
		t.Fatal("firstJobByCapability returned false, want created snmp job")
	}

	payload, err := jobtypes.ParseSNMPScanPayload(job.Payload)
	if err != nil {
		t.Fatalf("ParseSNMPScanPayload returned error: %v", err)
	}

	if len(payload.Targets) != 1 || payload.Targets[0].CIDR != "192.0.2.0/24" {
		t.Fatalf("payload.Targets = %#v, want one snmp target range", payload.Targets)
	}

	if payload.CredentialReference() != "snmp-v2c-default" {
		t.Fatalf("payload.CredentialReference() = %q, want %q", payload.CredentialReference(), "snmp-v2c-default")
	}

	if got := payload.Credential(); got.Community != "public" || got.Version != credentials.SNMPVersion2c {
		t.Fatalf("payload.Credential() = %#v, want snmp v2c public", got)
	}
}

func TestSchedulerRunOnceCreatesSSHJobsForDueSchedules(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	credentialProfile, err := store.CreateCredentialProfile(context.Background(), credentials.CreateRequest{
		SiteID:   "site-1",
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

	targetRange, err := store.CreateTargetRange(context.Background(), targets.CreateRequest{
		SiteID:     "site-1",
		Name:       "branch-a",
		CIDR:       "192.0.2.0/24",
		Exclusions: []string{"192.0.2.10"},
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := store.CreateScanProfile(context.Background(), profiles.CreateScanProfileRequest{
		SiteID:              "site-1",
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
	now := time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC)
	if _, err := store.CreateSchedule(context.Background(), schedules.CreateRequest{
		SiteID:         "site-1",
		Name:           "every-minute-ssh",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(store, func() time.Time { return now })
	created, err := scheduler.RunOnce(context.Background(), nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	job, ok := store.firstJobByCapability("ssh")
	if !ok {
		t.Fatal("firstJobByCapability returned false, want created ssh job")
	}

	payload, err := jobtypes.ParseSSHScanPayload(job.Payload)
	if err != nil {
		t.Fatalf("ParseSSHScanPayload returned error: %v", err)
	}

	if len(payload.Targets) != 1 || payload.Targets[0].CIDR != "192.0.2.0/24" {
		t.Fatalf("payload.Targets = %#v, want one ssh target range", payload.Targets)
	}

	if payload.CredentialReference() != "linux-ssh-default" {
		t.Fatalf("payload.CredentialReference() = %q, want %q", payload.CredentialReference(), "linux-ssh-default")
	}

	if got := payload.Credential(); got.Username != "observer" || got.Password != "secret-password" {
		t.Fatalf("payload.Credential() = %#v, want ssh password credential", got)
	}
}

func TestSchedulerRunOnceCreatesWinRMJobsForDueSchedules(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	credentialProfile, err := store.CreateCredentialProfile(context.Background(), credentials.CreateRequest{
		SiteID:   "site-1",
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

	targetRange, err := store.CreateTargetRange(context.Background(), targets.CreateRequest{
		SiteID:     "site-1",
		Name:       "branch-a",
		CIDR:       "192.0.2.0/24",
		Exclusions: []string{"192.0.2.10"},
	})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := store.CreateScanProfile(context.Background(), profiles.CreateScanProfileRequest{
		SiteID:              "site-1",
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
	now := time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC)
	if _, err := store.CreateSchedule(context.Background(), schedules.CreateRequest{
		SiteID:         "site-1",
		Name:           "every-minute-winrm",
		CronExpression: "* * * * *",
		TargetRangeID:  targetRange.ID,
		ScanProfileID:  scanProfile.ID,
		Enabled:        &enabled,
		Now:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	scheduler := newSchedulerService(store, func() time.Time { return now })
	created, err := scheduler.RunOnce(context.Background(), nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 1 {
		t.Fatalf("created = %d, want %d", created, 1)
	}

	job, ok := store.firstJobByCapability("winrm")
	if !ok {
		t.Fatal("firstJobByCapability returned false, want created winrm job")
	}

	payload, err := jobtypes.ParseWinRMScanPayload(job.Payload)
	if err != nil {
		t.Fatalf("ParseWinRMScanPayload returned error: %v", err)
	}

	if len(payload.Targets) != 1 || payload.Targets[0].CIDR != "192.0.2.0/24" {
		t.Fatalf("payload.Targets = %#v, want one winrm target range", payload.Targets)
	}

	if payload.CredentialReference() != "windows-winrm-default" {
		t.Fatalf("payload.CredentialReference() = %q, want %q", payload.CredentialReference(), "windows-winrm-default")
	}

	if got := payload.Credential(); got.Username != "administrator" || got.Password != "secret-password" {
		t.Fatalf("payload.Credential() = %#v, want winrm credential", got)
	}

	if !payload.UsesHTTPS() {
		t.Fatal("payload.UsesHTTPS() = false, want true")
	}
}

func TestSchedulerRunOnceAppliesObservationRetention(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	store := newScheduledMemoryStore()
	store.observations = []postgres.Observation{
		{ID: "obs-old", ObservedAt: now.Add(-48 * time.Hour)},
		{ID: "obs-new", ObservedAt: now.Add(-2 * time.Hour)},
	}

	scheduler := newSchedulerService(store, func() time.Time { return now }).WithObservationRetention(24 * time.Hour)
	created, err := scheduler.RunOnce(context.Background(), nil)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if created != 0 {
		t.Fatalf("created = %d, want %d", created, 0)
	}

	if len(store.observations) != 1 {
		t.Fatalf("len(observations) = %d, want %d", len(store.observations), 1)
	}

	if store.observations[0].ID != "obs-new" {
		t.Fatalf("observations[0].ID = %q, want %q", store.observations[0].ID, "obs-new")
	}
}
