package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
	protocolicmp "github.com/mbaybarsk/openbadger/internal/protocols/icmp"
	protocolsnmp "github.com/mbaybarsk/openbadger/internal/protocols/snmp"
	protocolssh "github.com/mbaybarsk/openbadger/internal/protocols/ssh"
	protocolwinrm "github.com/mbaybarsk/openbadger/internal/protocols/winrm"
)

func TestDemoRunnerRun(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, time.April, 4, 12, 45, 0, 0, time.UTC)
	runner := newDemoRunner(func() time.Time { return fixedNow })

	results, err := runner.Run(context.Background(), RunRequest{
		Job: jobtypes.Record{
			ID:         "job-demo-1",
			Kind:       "demo",
			Capability: "icmp",
		},
		Node: nodes.State{
			NodeID: "node-1",
			SiteID: "site-1",
			Kind:   nodes.KindCollector,
			Name:   "collector-1",
		},
		Version: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want %d", len(results), 1)
	}

	observation := results[0]
	if observation.SchemaVersion != observations.SchemaVersion {
		t.Fatalf("observation.SchemaVersion = %q, want %q", observation.SchemaVersion, observations.SchemaVersion)
	}

	if observation.Type != "icmp.alive" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "icmp.alive")
	}

	if observation.Scope != "sighting" {
		t.Fatalf("observation.Scope = %q, want %q", observation.Scope, "sighting")
	}

	if observation.SiteID != "site-1" {
		t.Fatalf("observation.SiteID = %q, want %q", observation.SiteID, "site-1")
	}

	if observation.JobID != "job-demo-1" {
		t.Fatalf("observation.JobID = %q, want %q", observation.JobID, "job-demo-1")
	}

	if !observation.ObservedAt.Equal(fixedNow) {
		t.Fatalf("observation.ObservedAt = %s, want %s", observation.ObservedAt, fixedNow)
	}

	if observation.Emitter == nil {
		t.Fatal("observation.Emitter = nil, want non-nil")
	}

	if observation.Emitter.ID != "node-1" {
		t.Fatalf("observation.Emitter.ID = %q, want %q", observation.Emitter.ID, "node-1")
	}

	if observation.Evidence == nil || observation.Evidence.SourceProtocol != "icmp" {
		t.Fatalf("observation.Evidence = %#v, want source protocol %q", observation.Evidence, "icmp")
	}

	if value, ok := observation.Facts["synthetic"].(bool); !ok || !value {
		t.Fatalf("observation.Facts[synthetic] = %#v, want true", observation.Facts["synthetic"])
	}
}

func TestICMPRunnerRun(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(jobtypes.ICMPScanPayload{
		Targets: []jobtypes.ICMPScanTarget{{
			CIDR:       "192.0.2.0/30",
			Exclusions: []string{"192.0.2.2"},
		}},
		TimeoutMS: 1000,
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	runner := newICMPRunner(stubICMPProber{
		results: map[string]protocolicmp.Result{
			"192.0.2.1": {
				IP:         netip.MustParseAddr("192.0.2.1"),
				RTT:        2 * time.Millisecond,
				TTL:        64,
				ObservedAt: time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC),
			},
		},
	}, func() time.Time { return time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC) })

	results, err := runner.Run(context.Background(), RunRequest{
		Job: jobtypes.Record{
			ID:         "job-icmp-1",
			Kind:       "scan",
			Capability: "icmp",
			Payload:    payload,
		},
		Node: nodes.State{
			NodeID: "node-1",
			SiteID: "site-1",
			Kind:   nodes.KindCollector,
			Name:   "collector-1",
		},
		Version: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want %d", len(results), 1)
	}

	if got := results[0].Target; got == nil || got.IP != "192.0.2.1" {
		t.Fatalf("results[0].Target = %#v, want IP %q", got, "192.0.2.1")
	}
}

type stubICMPProber struct {
	results map[string]protocolicmp.Result
	errs    map[string]error
}

func (s stubICMPProber) Probe(_ context.Context, ip netip.Addr, _ time.Duration) (protocolicmp.Result, error) {
	if err, ok := s.errs[ip.String()]; ok {
		return protocolicmp.Result{}, err
	}

	if result, ok := s.results[ip.String()]; ok {
		return result, nil
	}

	return protocolicmp.Result{}, protocolicmp.ErrNoReply
}

func TestICMPRunnerRunReturnsProbeErrors(t *testing.T) {
	t.Parallel()

	payload := json.RawMessage(`{"targets":[{"cidr":"192.0.2.1/32"}]}`)
	runner := newICMPRunner(stubICMPProber{errs: map[string]error{"192.0.2.1": errors.New("permission denied")}}, nil)

	_, err := runner.Run(context.Background(), RunRequest{
		Job:  jobtypes.Record{ID: "job-icmp-2", Kind: "scan", Capability: "icmp", Payload: payload},
		Node: nodes.State{NodeID: "node-1", SiteID: "site-1", Kind: nodes.KindCollector},
	})
	if err == nil {
		t.Fatal("Run returned nil error, want probe error")
	}
}

func TestSNMPRunnerRun(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(jobtypes.SNMPScanPayload{
		Targets:             []jobtypes.SNMPScanTarget{{CIDR: "192.0.2.10/32"}},
		Port:                161,
		CredentialProfileID: "cred-1",
		CredentialProfile: &credentials.Profile{
			ID:       "cred-1",
			Name:     "snmp-v2c-default",
			Protocol: credentials.ProtocolSNMP,
			SNMP: &credentials.SNMPProfile{
				Version:   credentials.SNMPVersion2c,
				Community: "public",
			},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	runner := newSNMPRunner(stubSNMPCollector{
		results: map[string]protocolsnmp.Result{
			"192.0.2.10": {
				System:     protocolsnmp.SystemData{SysName: "sw-core-01", SysDescr: "Cisco IOS XE Software, Version 17.9.3", SysObjectID: "1.3.6.1.4.1.9.1.2695", UptimeTicks: 123, EngineID: "8000000903001122334455"},
				Interfaces: []protocolsnmp.InterfaceData{{Index: 10101, Name: "Gi1/0/1", OperStatus: "up", AdminStatus: "up", MACAddress: "00:11:22:33:44:55"}},
				ARPEntries: []protocolsnmp.ARPEntry{{InterfaceIndex: 12, ObservedIP: "192.0.2.55", ObservedMAC: "aa:bb:cc:dd:ee:ff"}},
				FDBEntries: []protocolsnmp.FDBEntry{{BridgePort: 17, InterfaceIndex: 10101, ObservedMAC: "de:ad:be:ef:10:20", VLANID: 20}},
			},
		},
	}, func() time.Time { return time.Date(2026, time.April, 4, 13, 5, 0, 0, time.UTC) })

	results, err := runner.Run(context.Background(), RunRequest{
		Job:     jobtypes.Record{ID: "job-snmp-1", Kind: "scan", Capability: "snmp", Payload: payload},
		Node:    nodes.State{NodeID: "node-1", SiteID: "site-1", Kind: nodes.KindCollector, Name: "collector-1"},
		Version: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want %d", len(results), 4)
	}

	if results[0].Type != "snmp.system" || results[1].Type != "snmp.interface" || results[2].Type != "snmp.arp_entry" || results[3].Type != "snmp.fdb_entry" {
		t.Fatalf("types = [%q %q %q %q], want snmp observation sequence", results[0].Type, results[1].Type, results[2].Type, results[3].Type)
	}
}

type stubSNMPCollector struct {
	results map[string]protocolsnmp.Result
	errs    map[string]error
}

func (s stubSNMPCollector) Collect(_ context.Context, request protocolsnmp.Request) (protocolsnmp.Result, error) {
	if err, ok := s.errs[request.Target]; ok {
		return protocolsnmp.Result{}, err
	}

	if result, ok := s.results[request.Target]; ok {
		return result, nil
	}

	return protocolsnmp.Result{}, protocolsnmp.ErrNoResponse
}

func TestSSHRunnerRun(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(jobtypes.SSHScanPayload{
		Targets:             []jobtypes.SSHScanTarget{{CIDR: "192.0.2.10/32"}},
		Port:                22,
		CredentialProfileID: "cred-ssh-1",
		CredentialProfile: &credentials.Profile{
			ID:       "cred-ssh-1",
			Name:     "linux-ssh-default",
			Protocol: credentials.ProtocolSSH,
			SSH: &credentials.SSHProfile{
				Username: "observer",
				Password: "secret-password",
			},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	runner := newSSHRunner(stubSSHCollector{
		results: map[string]protocolssh.Result{
			"192.0.2.10": {
				Hostname:           "web-01",
				FQDN:               "web-01.example.local",
				OSRelease:          protocolssh.OSRelease{Name: "Ubuntu", Version: "22.04.4 LTS", ID: "ubuntu", PrettyName: "Ubuntu 22.04.4 LTS", VersionID: "22.04"},
				KernelVersion:      "6.8.0-31-generic",
				Architecture:       "x86_64",
				HostKeyFingerprint: "SHA256:abcdef1234567890",
				MachineID:          "0123456789abcdef0123456789abcdef",
			},
		},
	}, func() time.Time { return time.Date(2026, time.April, 4, 13, 10, 0, 0, time.UTC) })

	results, err := runner.Run(context.Background(), RunRequest{
		Job:     jobtypes.Record{ID: "job-ssh-1", Kind: "scan", Capability: "ssh", Payload: payload},
		Node:    nodes.State{NodeID: "node-1", SiteID: "site-1", Kind: nodes.KindCollector, Name: "collector-1"},
		Version: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want %d", len(results), 1)
	}

	observation := results[0]
	if observation.Type != "ssh.host" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "ssh.host")
	}

	if observation.Identifiers == nil || observation.Identifiers.FQDN != "web-01.example.local" {
		t.Fatalf("observation.Identifiers = %#v, want fqdn %q", observation.Identifiers, "web-01.example.local")
	}

	if observation.Evidence == nil || observation.Evidence.CredentialProfile != "linux-ssh-default" {
		t.Fatalf("observation.Evidence = %#v, want credential profile %q", observation.Evidence, "linux-ssh-default")
	}
}

func TestSSHRunnerSkipsNoResponse(t *testing.T) {
	t.Parallel()

	payload := json.RawMessage(`{"targets":[{"cidr":"192.0.2.10/32"}],"credential_profile":{"protocol":"ssh","ssh":{"username":"observer","password":"secret-password"}}}`)
	runner := newSSHRunner(stubSSHCollector{errs: map[string]error{"192.0.2.10": protocolssh.ErrNoResponse}}, nil)

	results, err := runner.Run(context.Background(), RunRequest{
		Job:  jobtypes.Record{ID: "job-ssh-2", Kind: "scan", Capability: "ssh", Payload: payload},
		Node: nodes.State{NodeID: "node-1", SiteID: "site-1", Kind: nodes.KindCollector},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}

type stubSSHCollector struct {
	results map[string]protocolssh.Result
	errs    map[string]error
}

func (s stubSSHCollector) Collect(_ context.Context, request protocolssh.Request) (protocolssh.Result, error) {
	if err, ok := s.errs[request.Target]; ok {
		return protocolssh.Result{}, err
	}

	if result, ok := s.results[request.Target]; ok {
		return result, nil
	}

	return protocolssh.Result{}, protocolssh.ErrNoResponse
}

func TestWinRMRunnerRun(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(jobtypes.WinRMScanPayload{
		Targets:             []jobtypes.WinRMScanTarget{{CIDR: "192.0.2.10/32"}},
		Port:                5986,
		CredentialProfileID: "cred-winrm-1",
		CredentialProfile: &credentials.Profile{
			ID:       "cred-winrm-1",
			Name:     "windows-winrm-default",
			Protocol: credentials.ProtocolWinRM,
			WinRM: &credentials.WinRMProfile{
				Username: "administrator",
				Password: "secret-password",
			},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	runner := newWinRMRunner(stubWinRMCollector{
		results: map[string]protocolwinrm.Result{
			"192.0.2.10": {
				Hostname:         "WSUS-01",
				Domain:           "example.local",
				OSName:           "Microsoft Windows Server 2022 Standard",
				OSVersion:        "10.0.20348",
				BuildNumber:      "20348",
				Manufacturer:     "Dell Inc.",
				Model:            "PowerEdge R650",
				SerialNumber:     "ABCDEF1",
				SystemUUID:       "7D9C1A4D-3F4F-4F0B-9159-9E4F7ACB2D83",
				NetworkAddresses: []string{"192.0.2.10", "fe80::1"},
			},
		},
	}, func() time.Time { return time.Date(2026, time.April, 4, 13, 15, 0, 0, time.UTC) })

	results, err := runner.Run(context.Background(), RunRequest{
		Job:     jobtypes.Record{ID: "job-winrm-1", Kind: "scan", Capability: "winrm", Payload: payload},
		Node:    nodes.State{NodeID: "node-1", SiteID: "site-1", Kind: nodes.KindCollector, Name: "collector-1"},
		Version: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want %d", len(results), 1)
	}

	observation := results[0]
	if observation.Type != "winrm.windows_host" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "winrm.windows_host")
	}

	if observation.Identifiers == nil || observation.Identifiers.SerialNumber != "ABCDEF1" {
		t.Fatalf("observation.Identifiers = %#v, want serial number %q", observation.Identifiers, "ABCDEF1")
	}

	if observation.Evidence == nil || observation.Evidence.CredentialProfile != "windows-winrm-default" {
		t.Fatalf("observation.Evidence = %#v, want credential profile %q", observation.Evidence, "windows-winrm-default")
	}
}

func TestWinRMRunnerSkipsNoResponse(t *testing.T) {
	t.Parallel()

	payload := json.RawMessage(`{"targets":[{"cidr":"192.0.2.10/32"}],"credential_profile":{"protocol":"winrm","winrm":{"username":"administrator","password":"secret-password"}}}`)
	runner := newWinRMRunner(stubWinRMCollector{errs: map[string]error{"192.0.2.10": protocolwinrm.ErrNoResponse}}, nil)

	results, err := runner.Run(context.Background(), RunRequest{
		Job:  jobtypes.Record{ID: "job-winrm-2", Kind: "scan", Capability: "winrm", Payload: payload},
		Node: nodes.State{NodeID: "node-1", SiteID: "site-1", Kind: nodes.KindCollector},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}

type stubWinRMCollector struct {
	results map[string]protocolwinrm.Result
	errs    map[string]error
}

func (s stubWinRMCollector) Collect(_ context.Context, request protocolwinrm.Request) (protocolwinrm.Result, error) {
	if err, ok := s.errs[request.Target]; ok {
		return protocolwinrm.Result{}, err
	}

	if result, ok := s.results[request.Target]; ok {
		return result, nil
	}

	return protocolwinrm.Result{}, protocolwinrm.ErrNoResponse
}
