package winrm

import (
	"testing"
	"time"
)

func TestNormalizeObservationsWindowsHost(t *testing.T) {
	t.Parallel()

	observations, err := NormalizeObservations(NormalizeContext{
		SiteID:            "site-1",
		JobID:             "job-1",
		NodeKind:          "collector",
		NodeID:            "node-1",
		NodeName:          "collector-1",
		Version:           "0.1.0",
		TargetInput:       "192.0.2.10",
		TargetIP:          "192.0.2.10",
		Port:              5986,
		ObservedAt:        time.Date(2026, time.April, 4, 13, 20, 0, 0, time.UTC),
		CredentialProfile: "windows-winrm-default",
	}, Result{
		Hostname:         "WSUS-01",
		Domain:           "example.local",
		OSName:           "Microsoft Windows Server 2022 Standard",
		OSVersion:        "10.0.20348",
		BuildNumber:      "20348",
		Manufacturer:     "Dell Inc.",
		Model:            "PowerEdge R650",
		SerialNumber:     "ABCDEF1",
		SystemUUID:       "7D9C1A4D-3F4F-4F0B-9159-9E4F7ACB2D83",
		NetworkAddresses: []string{"192.0.2.10", "fe80::1", "not-an-ip"},
	})
	if err != nil {
		t.Fatalf("NormalizeObservations returned error: %v", err)
	}

	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want %d", len(observations), 1)
	}

	observation := observations[0]
	if observation.Type != "winrm.windows_host" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "winrm.windows_host")
	}

	if observation.Identifiers == nil {
		t.Fatal("observation.Identifiers = nil, want non-nil")
	}

	if observation.Identifiers.FQDN != "wsus-01.example.local" {
		t.Fatalf("observation.Identifiers.FQDN = %q, want %q", observation.Identifiers.FQDN, "wsus-01.example.local")
	}

	if observation.Identifiers.SystemUUID != "7d9c1a4d-3f4f-4f0b-9159-9e4f7acb2d83" {
		t.Fatalf("observation.Identifiers.SystemUUID = %q, want canonical uuid", observation.Identifiers.SystemUUID)
	}

	if observation.Addresses == nil || len(observation.Addresses.IPAddresses) != 2 {
		t.Fatalf("observation.Addresses = %#v, want target and ipv6 addresses", observation.Addresses)
	}

	if observation.Facts["hostname"] != "WSUS-01" {
		t.Fatalf("observation.Facts[hostname] = %#v, want %q", observation.Facts["hostname"], "WSUS-01")
	}

	if observation.Evidence == nil || observation.Evidence.CredentialProfile != "windows-winrm-default" {
		t.Fatalf("observation.Evidence = %#v, want credential profile %q", observation.Evidence, "windows-winrm-default")
	}
}

func TestNormalizeObservationsValidation(t *testing.T) {
	t.Parallel()

	_, err := NormalizeObservations(NormalizeContext{}, Result{})
	if err == nil {
		t.Fatal("NormalizeObservations() error = nil, want validation error")
	}

	if err.Error() != "winrm observation site id is required" {
		t.Fatalf("NormalizeObservations() error = %q, want %q", err.Error(), "winrm observation site id is required")
	}
}
