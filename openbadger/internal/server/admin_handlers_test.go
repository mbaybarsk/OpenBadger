package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

func TestDebugTargetRangesHandlerCreatesTargetRange(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	handler := newHandler(HandlerOptions{TargetRangeService: newTargetRangeService(store)})

	req := httptest.NewRequest(http.MethodPost, "/debug/target-ranges", strings.NewReader(`{"site_id":"site-1","name":"branch-a","cidr":"192.0.2.0/24","exclusions":["192.0.2.10"]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response targets.DebugCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.TargetRange.Name != "branch-a" {
		t.Fatalf("response.TargetRange.Name = %q, want %q", response.TargetRange.Name, "branch-a")
	}
}

func TestDebugScanProfilesHandlerCreatesScanProfile(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	handler := newHandler(HandlerOptions{ScanProfileService: newScanProfileService(store)})

	req := httptest.NewRequest(http.MethodPost, "/debug/scan-profiles", strings.NewReader(`{"site_id":"site-1","name":"icmp-default","capability":"icmp","timeout_ms":1500,"retry_count":1,"concurrency":4}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response profiles.DebugCreateScanProfileResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.ScanProfile.Capability != "icmp" {
		t.Fatalf("response.ScanProfile.Capability = %q, want %q", response.ScanProfile.Capability, "icmp")
	}
}

func TestDebugCredentialProfilesHandlerCreatesCredentialProfile(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	handler := newHandler(HandlerOptions{CredentialProfileService: newCredentialProfileService(store)})

	req := httptest.NewRequest(http.MethodPost, "/debug/credential-profiles", strings.NewReader(`{"site_id":"site-1","name":"snmp-v2c-default","protocol":"snmp","snmp":{"version":"v2c","community":"public"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response credentials.DebugCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.CredentialProfile.Protocol != credentials.ProtocolSNMP {
		t.Fatalf("response.CredentialProfile.Protocol = %q, want %q", response.CredentialProfile.Protocol, credentials.ProtocolSNMP)
	}

	if response.CredentialProfile.SNMP == nil || response.CredentialProfile.SNMP.Community != "" {
		t.Fatalf("response.CredentialProfile.SNMP = %#v, want redacted community", response.CredentialProfile.SNMP)
	}
}

func TestDebugCredentialProfilesHandlerCreatesSSHCredentialProfile(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	handler := newHandler(HandlerOptions{CredentialProfileService: newCredentialProfileService(store)})

	req := httptest.NewRequest(http.MethodPost, "/debug/credential-profiles", strings.NewReader(`{"site_id":"site-1","name":"linux-ssh-default","protocol":"ssh","ssh":{"username":"observer","password":"secret-password"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response credentials.DebugCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.CredentialProfile.Protocol != credentials.ProtocolSSH {
		t.Fatalf("response.CredentialProfile.Protocol = %q, want %q", response.CredentialProfile.Protocol, credentials.ProtocolSSH)
	}

	if response.CredentialProfile.SSH == nil || response.CredentialProfile.SSH.Password != "" {
		t.Fatalf("response.CredentialProfile.SSH = %#v, want redacted password", response.CredentialProfile.SSH)
	}
}

func TestDebugCredentialProfilesHandlerCreatesWinRMCredentialProfile(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	handler := newHandler(HandlerOptions{CredentialProfileService: newCredentialProfileService(store)})

	req := httptest.NewRequest(http.MethodPost, "/debug/credential-profiles", strings.NewReader(`{"site_id":"site-1","name":"windows-winrm-default","protocol":"winrm","winrm":{"username":"administrator","password":"secret-password"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response credentials.DebugCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.CredentialProfile.Protocol != credentials.ProtocolWinRM {
		t.Fatalf("response.CredentialProfile.Protocol = %q, want %q", response.CredentialProfile.Protocol, credentials.ProtocolWinRM)
	}

	if response.CredentialProfile.WinRM == nil || response.CredentialProfile.WinRM.Password != "" {
		t.Fatalf("response.CredentialProfile.WinRM = %#v, want redacted password", response.CredentialProfile.WinRM)
	}
}

func TestDebugSchedulesHandlerCreatesSchedule(t *testing.T) {
	t.Parallel()

	store := newScheduledMemoryStore()
	targetRange, err := store.CreateTargetRange(context.Background(), targets.CreateRequest{SiteID: "site-1", Name: "branch-a", CIDR: "192.0.2.0/24"})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	profile, err := store.CreateScanProfile(context.Background(), profiles.CreateScanProfileRequest{SiteID: "site-1", Name: "icmp-default", Capability: "icmp"})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	handler := newHandler(HandlerOptions{ScheduleService: newScheduleService(store)})
	req := httptest.NewRequest(http.MethodPost, "/debug/schedules", strings.NewReader(`{"site_id":"site-1","name":"every-five","cron_expression":"*/5 * * * *","target_range_id":"`+targetRange.ID+`","scan_profile_id":"`+profile.ID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var response schedules.DebugCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if response.Schedule.NextRunAt.Before(time.Date(2026, time.April, 4, 9, 42, 0, 0, time.UTC)) {
		t.Fatalf("response.Schedule.NextRunAt = %s, want non-zero future run", response.Schedule.NextRunAt)
	}
}
