package jobs

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

func TestParseICMPScanPayload(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30","exclusions":["192.0.2.1"]}],"timeout_ms":1500}`)
	payload, err := ParseICMPScanPayload(raw)
	if err != nil {
		t.Fatalf("ParseICMPScanPayload returned error: %v", err)
	}

	if got, want := payload.Timeout(), 1500*time.Millisecond; got != want {
		t.Fatalf("payload.Timeout() = %s, want %s", got, want)
	}

	if got, want := payload.TargetRanges(), []targets.Range{{CIDR: "192.0.2.0/30", Exclusions: []string{"192.0.2.1"}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payload.TargetRanges() = %#v, want %#v", got, want)
	}
}

func TestParseICMPScanPayloadValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{name: "missing payload", raw: nil, want: "icmp job payload is required"},
		{name: "missing targets", raw: json.RawMessage(`{"timeout_ms":1000}`), want: "icmp job payload targets are required"},
		{name: "missing cidr", raw: json.RawMessage(`{"targets":[{}]}`), want: "icmp job payload targets[0].cidr is required"},
		{name: "negative timeout", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}],"timeout_ms":-1}`), want: "icmp job payload timeout_ms is invalid"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseICMPScanPayload(tt.raw)
			if err == nil {
				t.Fatalf("ParseICMPScanPayload() error = nil, want %q", tt.want)
			}

			if err.Error() != tt.want {
				t.Fatalf("ParseICMPScanPayload() error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestParseSNMPScanPayload(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30","exclusions":["192.0.2.2"]}],"timeout_ms":2500,"retry_count":1,"credential_profile_id":"cred-1","credential_profile":{"id":"cred-1","name":"snmp-v2c-default","protocol":"snmp","snmp":{"version":"v2c","community":"public","port":161}}}`)
	payload, err := ParseSNMPScanPayload(raw)
	if err != nil {
		t.Fatalf("ParseSNMPScanPayload returned error: %v", err)
	}

	if got, want := payload.Timeout(), 2500*time.Millisecond; got != want {
		t.Fatalf("payload.Timeout() = %s, want %s", got, want)
	}

	if got, want := payload.EffectivePort(), 161; got != want {
		t.Fatalf("payload.EffectivePort() = %d, want %d", got, want)
	}

	if got, want := payload.TargetRanges(), []targets.Range{{CIDR: "192.0.2.0/30", Exclusions: []string{"192.0.2.2"}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payload.TargetRanges() = %#v, want %#v", got, want)
	}

	if got := payload.Credential(); got.Version != credentials.SNMPVersion2c || got.Community != "public" {
		t.Fatalf("payload.Credential() = %#v, want snmp v2c public", got)
	}

	if got := payload.CredentialReference(); got != "snmp-v2c-default" {
		t.Fatalf("payload.CredentialReference() = %q, want %q", got, "snmp-v2c-default")
	}
}

func TestParseSNMPScanPayloadValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{name: "missing payload", raw: nil, want: "snmp job payload is required"},
		{name: "missing targets", raw: json.RawMessage(`{"credential_profile":{"protocol":"snmp","snmp":{"version":"v2c","community":"public"}}}`), want: "snmp job payload targets are required"},
		{name: "missing credential profile", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}]}`), want: "snmp job payload credential profile is required"},
		{name: "invalid port", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}],"port":70000,"credential_profile":{"protocol":"snmp","snmp":{"version":"v2c","community":"public"}}}`), want: "snmp job payload port is invalid"},
		{name: "invalid snmp settings", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}],"credential_profile":{"protocol":"snmp","snmp":{"version":"v3","username":"observer","privacy_protocol":"aes","privacy_password":"secret"}}}`), want: "credential profile snmp privacy requires authentication settings"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseSNMPScanPayload(tt.raw)
			if err == nil {
				t.Fatalf("ParseSNMPScanPayload() error = nil, want %q", tt.want)
			}

			if err.Error() != tt.want {
				t.Fatalf("ParseSNMPScanPayload() error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestParseSSHScanPayload(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30","exclusions":["192.0.2.2"]}],"timeout_ms":5000,"credential_profile_id":"cred-ssh-1","credential_profile":{"id":"cred-ssh-1","name":"linux-ssh-default","protocol":"ssh","ssh":{"username":"observer","password":"secret-password","port":22}}}`)
	payload, err := ParseSSHScanPayload(raw)
	if err != nil {
		t.Fatalf("ParseSSHScanPayload returned error: %v", err)
	}

	if got, want := payload.Timeout(), 5*time.Second; got != want {
		t.Fatalf("payload.Timeout() = %s, want %s", got, want)
	}

	if got, want := payload.EffectivePort(), 22; got != want {
		t.Fatalf("payload.EffectivePort() = %d, want %d", got, want)
	}

	if got, want := payload.TargetRanges(), []targets.Range{{CIDR: "192.0.2.0/30", Exclusions: []string{"192.0.2.2"}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payload.TargetRanges() = %#v, want %#v", got, want)
	}

	if got := payload.Credential(); got.Username != "observer" || got.Password != "secret-password" {
		t.Fatalf("payload.Credential() = %#v, want ssh password credential", got)
	}

	if got := payload.CredentialReference(); got != "linux-ssh-default" {
		t.Fatalf("payload.CredentialReference() = %q, want %q", got, "linux-ssh-default")
	}
}

func TestParseSSHScanPayloadValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{name: "missing payload", raw: nil, want: "ssh job payload is required"},
		{name: "missing targets", raw: json.RawMessage(`{"credential_profile":{"protocol":"ssh","ssh":{"username":"observer","password":"secret"}}}`), want: "ssh job payload targets are required"},
		{name: "missing credential profile", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}]}`), want: "ssh job payload credential profile is required"},
		{name: "invalid port", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}],"port":70000,"credential_profile":{"protocol":"ssh","ssh":{"username":"observer","password":"secret"}}}`), want: "ssh job payload port is invalid"},
		{name: "invalid ssh settings", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}],"credential_profile":{"protocol":"ssh","ssh":{"username":"observer","password":"secret","private_key":"bogus"}}}`), want: "credential profile ssh auth must use either password or private key"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseSSHScanPayload(tt.raw)
			if err == nil {
				t.Fatalf("ParseSSHScanPayload() error = nil, want %q", tt.want)
			}

			if err.Error() != tt.want {
				t.Fatalf("ParseSSHScanPayload() error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestParseWinRMScanPayload(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30","exclusions":["192.0.2.2"]}],"timeout_ms":5000,"credential_profile_id":"cred-winrm-1","credential_profile":{"id":"cred-winrm-1","name":"windows-winrm-default","protocol":"winrm","winrm":{"username":"administrator","password":"secret-password","use_https":true,"port":5986}}}`)
	payload, err := ParseWinRMScanPayload(raw)
	if err != nil {
		t.Fatalf("ParseWinRMScanPayload returned error: %v", err)
	}

	if got, want := payload.Timeout(), 5*time.Second; got != want {
		t.Fatalf("payload.Timeout() = %s, want %s", got, want)
	}

	if got, want := payload.EffectivePort(), 5986; got != want {
		t.Fatalf("payload.EffectivePort() = %d, want %d", got, want)
	}

	if got, want := payload.TargetRanges(), []targets.Range{{CIDR: "192.0.2.0/30", Exclusions: []string{"192.0.2.2"}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payload.TargetRanges() = %#v, want %#v", got, want)
	}

	if got := payload.Credential(); got.Username != "administrator" || got.Password != "secret-password" {
		t.Fatalf("payload.Credential() = %#v, want winrm credential", got)
	}

	if got := payload.CredentialReference(); got != "windows-winrm-default" {
		t.Fatalf("payload.CredentialReference() = %q, want %q", got, "windows-winrm-default")
	}

	if !payload.UsesHTTPS() {
		t.Fatal("payload.UsesHTTPS() = false, want true")
	}
}

func TestParseWinRMScanPayloadValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{name: "missing payload", raw: nil, want: "winrm job payload is required"},
		{name: "missing targets", raw: json.RawMessage(`{"credential_profile":{"protocol":"winrm","winrm":{"username":"administrator","password":"secret"}}}`), want: "winrm job payload targets are required"},
		{name: "missing credential profile", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}]}`), want: "winrm job payload credential profile is required"},
		{name: "invalid port", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}],"port":70000,"credential_profile":{"protocol":"winrm","winrm":{"username":"administrator","password":"secret"}}}`), want: "winrm job payload port is invalid"},
		{name: "http not explicitly allowed", raw: json.RawMessage(`{"targets":[{"cidr":"192.0.2.0/30"}],"credential_profile":{"protocol":"winrm","winrm":{"username":"administrator","password":"secret","use_https":false}}}`), want: "credential profile winrm http requires allow_http"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseWinRMScanPayload(tt.raw)
			if err == nil {
				t.Fatalf("ParseWinRMScanPayload() error = nil, want %q", tt.want)
			}

			if err.Error() != tt.want {
				t.Fatalf("ParseWinRMScanPayload() error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}
