package ssh

import (
	"testing"
	"time"
)

func TestNormalizeObservations(t *testing.T) {
	t.Parallel()

	results, err := NormalizeObservations(NormalizeContext{
		SiteID:            "site-1",
		JobID:             "job-ssh-1",
		NodeKind:          "collector",
		NodeID:            "node-1",
		NodeName:          "collector-1",
		Version:           "0.1.0",
		TargetInput:       "192.0.2.10",
		TargetIP:          "192.0.2.10",
		Port:              22,
		ObservedAt:        time.Date(2026, time.April, 4, 13, 15, 0, 0, time.UTC),
		CredentialProfile: "linux-ssh-default",
	}, Result{
		Hostname:           "Web-01",
		FQDN:               "Web-01.Example.Local",
		OSRelease:          OSRelease{Name: "Ubuntu", Version: "22.04.4 LTS", PrettyName: "Ubuntu 22.04.4 LTS", ID: "ubuntu", VersionID: "22.04"},
		KernelVersion:      "6.8.0-31-generic",
		Architecture:       "x86_64",
		HostKeyFingerprint: "SHA256:abcdef1234567890",
		MachineID:          "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("NormalizeObservations returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want %d", len(results), 1)
	}

	observation := results[0]
	if observation.Type != "ssh.host" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "ssh.host")
	}

	if observation.Identifiers == nil || observation.Identifiers.FQDN != "web-01.example.local" {
		t.Fatalf("observation.Identifiers = %#v, want normalized fqdn", observation.Identifiers)
	}

	if observation.Evidence == nil || observation.Evidence.CredentialProfile != "linux-ssh-default" {
		t.Fatalf("observation.Evidence = %#v, want credential profile %q", observation.Evidence, "linux-ssh-default")
	}

	if observation.Facts["hostname"] != "web-01" || observation.Facts["kernel_version"] != "6.8.0-31-generic" {
		t.Fatalf("observation.Facts = %#v, want normalized ssh host facts", observation.Facts)
	}
}
