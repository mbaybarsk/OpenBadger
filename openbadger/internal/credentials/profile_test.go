package credentials

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestValidateCreateRequestSNMPv2c(t *testing.T) {
	t.Parallel()

	err := ValidateCreateRequest(CreateRequest{
		SiteID:   "site-1",
		Name:     "snmp-v2c-default",
		Protocol: ProtocolSNMP,
		SNMP: &SNMPProfile{
			Version:   SNMPVersion2c,
			Community: "public",
		},
	})
	if err != nil {
		t.Fatalf("ValidateCreateRequest returned error: %v", err)
	}
}

func TestValidateCreateRequestSNMPv3AuthPriv(t *testing.T) {
	t.Parallel()

	err := ValidateCreateRequest(CreateRequest{
		SiteID:   "site-1",
		Name:     "snmp-v3-secure",
		Protocol: ProtocolSNMP,
		SNMP: &SNMPProfile{
			Version:         SNMPVersion3,
			Username:        "observer",
			AuthProtocol:    "sha256",
			AuthPassword:    "auth-secret",
			PrivacyProtocol: "aes256",
			PrivacyPassword: "priv-secret",
		},
	})
	if err != nil {
		t.Fatalf("ValidateCreateRequest returned error: %v", err)
	}
}

func TestValidateCreateRequestSSHPassword(t *testing.T) {
	t.Parallel()

	err := ValidateCreateRequest(CreateRequest{
		SiteID:   "site-1",
		Name:     "linux-ssh-password",
		Protocol: ProtocolSSH,
		SSH: &SSHProfile{
			Username: "observer",
			Password: "secret-password",
		},
	})
	if err != nil {
		t.Fatalf("ValidateCreateRequest returned error: %v", err)
	}
}

func TestValidateCreateRequestSSHPrivateKey(t *testing.T) {
	t.Parallel()

	err := ValidateCreateRequest(CreateRequest{
		SiteID:   "site-1",
		Name:     "linux-ssh-key",
		Protocol: ProtocolSSH,
		SSH: &SSHProfile{
			Username:   "observer",
			PrivateKey: mustGenerateSSHPrivateKeyPEM(t),
		},
	})
	if err != nil {
		t.Fatalf("ValidateCreateRequest returned error: %v", err)
	}
}

func TestValidateCreateRequestWinRMHTTPS(t *testing.T) {
	t.Parallel()

	err := ValidateCreateRequest(CreateRequest{
		SiteID:   "site-1",
		Name:     "windows-winrm-default",
		Protocol: ProtocolWinRM,
		WinRM: &WinRMProfile{
			Username: "administrator",
			Password: "secret-password",
		},
	})
	if err != nil {
		t.Fatalf("ValidateCreateRequest returned error: %v", err)
	}
}

func TestValidateCreateRequestWinRMHTTPAllowed(t *testing.T) {
	t.Parallel()

	err := ValidateCreateRequest(CreateRequest{
		SiteID:   "site-1",
		Name:     "windows-winrm-http",
		Protocol: ProtocolWinRM,
		WinRM: &WinRMProfile{
			Username:  "administrator",
			Password:  "secret-password",
			UseHTTPS:  boolRef(false),
			AllowHTTP: true,
		},
	})
	if err != nil {
		t.Fatalf("ValidateCreateRequest returned error: %v", err)
	}
}

func TestValidateCreateRequestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  CreateRequest
		want string
	}{
		{
			name: "missing site",
			req: CreateRequest{
				Name:     "snmp-v2c-default",
				Protocol: ProtocolSNMP,
				SNMP:     &SNMPProfile{Version: SNMPVersion2c, Community: "public"},
			},
			want: "credential profile site id is required",
		},
		{
			name: "missing snmp settings",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "snmp-v2c-default",
				Protocol: ProtocolSNMP,
			},
			want: "credential profile snmp settings are required",
		},
		{
			name: "missing v2c community",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "snmp-v2c-default",
				Protocol: ProtocolSNMP,
				SNMP:     &SNMPProfile{Version: SNMPVersion2c},
			},
			want: `credential profile snmp community is required for version "v2c"`,
		},
		{
			name: "v3 privacy without auth",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "snmp-v3-default",
				Protocol: ProtocolSNMP,
				SNMP: &SNMPProfile{
					Version:         SNMPVersion3,
					Username:        "observer",
					PrivacyProtocol: "aes",
					PrivacyPassword: "priv-secret",
				},
			},
			want: "credential profile snmp privacy requires authentication settings",
		},
		{
			name: "invalid auth protocol",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "snmp-v3-default",
				Protocol: ProtocolSNMP,
				SNMP: &SNMPProfile{
					Version:      SNMPVersion3,
					Username:     "observer",
					AuthProtocol: "bogus",
					AuthPassword: "auth-secret",
				},
			},
			want: `credential profile snmp auth protocol "bogus" is invalid`,
		},
		{
			name: "missing ssh username",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "linux-ssh-password",
				Protocol: ProtocolSSH,
				SSH: &SSHProfile{
					Password: "secret-password",
				},
			},
			want: "credential profile ssh username is required",
		},
		{
			name: "missing ssh secret",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "linux-ssh-password",
				Protocol: ProtocolSSH,
				SSH: &SSHProfile{
					Username: "observer",
				},
			},
			want: "credential profile ssh password or private key is required",
		},
		{
			name: "ssh password and private key together",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "linux-ssh-invalid",
				Protocol: ProtocolSSH,
				SSH: &SSHProfile{
					Username:   "observer",
					Password:   "secret-password",
					PrivateKey: mustGenerateSSHPrivateKeyPEM(t),
				},
			},
			want: "credential profile ssh auth must use either password or private key",
		},
		{
			name: "invalid ssh private key",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "linux-ssh-invalid-key",
				Protocol: ProtocolSSH,
				SSH: &SSHProfile{
					Username:   "observer",
					PrivateKey: "not-a-private-key",
				},
			},
			want: "credential profile ssh private key is invalid",
		},
		{
			name: "missing winrm username",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "windows-winrm-default",
				Protocol: ProtocolWinRM,
				WinRM: &WinRMProfile{
					Password: "secret-password",
				},
			},
			want: "credential profile winrm username is required",
		},
		{
			name: "missing winrm password",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "windows-winrm-default",
				Protocol: ProtocolWinRM,
				WinRM: &WinRMProfile{
					Username: "administrator",
				},
			},
			want: "credential profile winrm password is required",
		},
		{
			name: "winrm http requires explicit allow",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "windows-winrm-http",
				Protocol: ProtocolWinRM,
				WinRM: &WinRMProfile{
					Username: "administrator",
					Password: "secret-password",
					UseHTTPS: boolRef(false),
				},
			},
			want: "credential profile winrm http requires allow_http",
		},
		{
			name: "invalid winrm port",
			req: CreateRequest{
				SiteID:   "site-1",
				Name:     "windows-winrm-default",
				Protocol: ProtocolWinRM,
				WinRM: &WinRMProfile{
					Port:     70000,
					Username: "administrator",
					Password: "secret-password",
				},
			},
			want: "credential profile winrm port is invalid",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateCreateRequest(tt.req)
			if err == nil {
				t.Fatalf("ValidateCreateRequest() error = nil, want %q", tt.want)
			}

			if err.Error() != tt.want {
				t.Fatalf("ValidateCreateRequest() error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestProfileSanitizedSSH(t *testing.T) {
	t.Parallel()

	profile := Profile{
		ID:       "cred-ssh-1",
		SiteID:   "site-1",
		Name:     "linux-ssh-key",
		Protocol: ProtocolSSH,
		SSH: &SSHProfile{
			Username:   "observer",
			Password:   "secret-password",
			PrivateKey: mustGenerateSSHPrivateKeyPEM(t),
			Passphrase: "top-secret",
		},
	}

	sanitized := profile.Sanitized()
	if sanitized.SSH == nil {
		t.Fatal("sanitized.SSH = nil, want non-nil")
	}

	if sanitized.SSH.Password != "" || sanitized.SSH.PrivateKey != "" || sanitized.SSH.Passphrase != "" {
		t.Fatalf("sanitized.SSH = %#v, want secrets redacted", sanitized.SSH)
	}
}

func TestProfileSanitizedWinRM(t *testing.T) {
	t.Parallel()

	profile := Profile{
		ID:       "cred-winrm-1",
		SiteID:   "site-1",
		Name:     "windows-winrm-default",
		Protocol: ProtocolWinRM,
		WinRM: &WinRMProfile{
			Username: "administrator",
			Password: "secret-password",
		},
	}

	sanitized := profile.Sanitized()
	if sanitized.WinRM == nil {
		t.Fatal("sanitized.WinRM = nil, want non-nil")
	}

	if sanitized.WinRM.Password != "" {
		t.Fatalf("sanitized.WinRM = %#v, want password redacted", sanitized.WinRM)
	}
}

func mustGenerateSSHPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	return string(pem.EncodeToMemory(block))
}

func TestProfileSanitized(t *testing.T) {
	t.Parallel()

	profile := Profile{
		ID:       "cred-1",
		SiteID:   "site-1",
		Name:     "snmp-v3-default",
		Protocol: ProtocolSNMP,
		SNMP: &SNMPProfile{
			Version:         SNMPVersion3,
			Username:        "observer",
			Community:       "public",
			AuthPassword:    "auth-secret",
			PrivacyPassword: "priv-secret",
		},
	}

	sanitized := profile.Sanitized()
	if sanitized.SNMP == nil {
		t.Fatal("sanitized.SNMP = nil, want non-nil")
	}

	if sanitized.SNMP.Community != "" || sanitized.SNMP.AuthPassword != "" || sanitized.SNMP.PrivacyPassword != "" {
		t.Fatalf("sanitized.SNMP = %#v, want secrets redacted", sanitized.SNMP)
	}
}

func boolRef(value bool) *bool {
	return &value
}
