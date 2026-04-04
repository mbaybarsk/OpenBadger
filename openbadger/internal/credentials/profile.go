package credentials

import (
	"errors"
	"fmt"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

const (
	ProtocolSNMP  = "snmp"
	ProtocolSSH   = "ssh"
	ProtocolWinRM = "winrm"

	SNMPVersion2c = "v2c"
	SNMPVersion3  = "v3"
)

var ErrNotFound = errors.New("credential profile not found")

type Profile struct {
	ID        string        `json:"id"`
	SiteID    string        `json:"site_id"`
	Name      string        `json:"name"`
	Protocol  string        `json:"protocol"`
	SNMP      *SNMPProfile  `json:"snmp,omitempty"`
	SSH       *SSHProfile   `json:"ssh,omitempty"`
	WinRM     *WinRMProfile `json:"winrm,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

type SNMPProfile struct {
	Version         string `json:"version"`
	Port            int    `json:"port,omitempty"`
	Community       string `json:"community,omitempty"`
	Username        string `json:"username,omitempty"`
	ContextName     string `json:"context_name,omitempty"`
	AuthProtocol    string `json:"auth_protocol,omitempty"`
	AuthPassword    string `json:"auth_password,omitempty"`
	PrivacyProtocol string `json:"privacy_protocol,omitempty"`
	PrivacyPassword string `json:"privacy_password,omitempty"`
}

type SSHProfile struct {
	Port       int    `json:"port,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type WinRMProfile struct {
	Port          int    `json:"port,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	UseHTTPS      *bool  `json:"use_https,omitempty"`
	AllowHTTP     bool   `json:"allow_http,omitempty"`
	InsecureTLS   bool   `json:"insecure_tls,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
}

type CreateRequest struct {
	SiteID   string        `json:"site_id"`
	Name     string        `json:"name"`
	Protocol string        `json:"protocol"`
	SNMP     *SNMPProfile  `json:"snmp,omitempty"`
	SSH      *SSHProfile   `json:"ssh,omitempty"`
	WinRM    *WinRMProfile `json:"winrm,omitempty"`
}

type DebugCreateResponse struct {
	CredentialProfile Profile `json:"credential_profile"`
}

func NormalizeProtocol(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func NormalizeSNMPVersion(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "2c", "v2c", "snmpv2c":
		return SNMPVersion2c
	case "3", "v3", "snmpv3":
		return SNMPVersion3
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func NormalizeSNMPAuthProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none":
		return ""
	case "md5":
		return "md5"
	case "sha", "sha1", "sha-1":
		return "sha"
	case "sha224", "sha-224":
		return "sha224"
	case "sha256", "sha-256":
		return "sha256"
	case "sha384", "sha-384":
		return "sha384"
	case "sha512", "sha-512":
		return "sha512"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func NormalizeSNMPPrivacyProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none":
		return ""
	case "des":
		return "des"
	case "aes", "aes128", "aes-128":
		return "aes"
	case "aes192", "aes-192":
		return "aes192"
	case "aes256", "aes-256":
		return "aes256"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func DefaultSNMPPort(port int) int {
	if port <= 0 {
		return 161
	}

	return port
}

func DefaultSSHPort(port int) int {
	if port <= 0 {
		return 22
	}

	return port
}

func DefaultWinRMPort(port int, https bool) int {
	if port > 0 {
		return port
	}

	if https {
		return 5986
	}

	return 5985
}

func CloneSNMPProfile(profile *SNMPProfile) *SNMPProfile {
	if profile == nil {
		return nil
	}

	copy := *profile
	return &copy
}

func CloneSSHProfile(profile *SSHProfile) *SSHProfile {
	if profile == nil {
		return nil
	}

	copy := *profile
	return &copy
}

func CloneWinRMProfile(profile *WinRMProfile) *WinRMProfile {
	if profile == nil {
		return nil
	}

	copy := *profile
	if profile.UseHTTPS != nil {
		useHTTPS := *profile.UseHTTPS
		copy.UseHTTPS = &useHTTPS
	}

	return &copy
}

func WinRMUsesHTTPS(profile *WinRMProfile) bool {
	if profile == nil || profile.UseHTTPS == nil {
		return true
	}

	return *profile.UseHTTPS
}

func CloneProfile(profile *Profile) *Profile {
	if profile == nil {
		return nil
	}

	copy := *profile
	copy.SNMP = CloneSNMPProfile(profile.SNMP)
	copy.SSH = CloneSSHProfile(profile.SSH)
	copy.WinRM = CloneWinRMProfile(profile.WinRM)
	return &copy
}

func (p Profile) Sanitized() Profile {
	copy := p
	copy.SNMP = CloneSNMPProfile(p.SNMP)
	copy.SSH = CloneSSHProfile(p.SSH)
	copy.WinRM = CloneWinRMProfile(p.WinRM)
	if copy.SNMP != nil {
		copy.SNMP.Community = ""
		copy.SNMP.AuthPassword = ""
		copy.SNMP.PrivacyPassword = ""
	}
	if copy.SSH != nil {
		copy.SSH.Password = ""
		copy.SSH.PrivateKey = ""
		copy.SSH.Passphrase = ""
	}
	if copy.WinRM != nil {
		copy.WinRM.Password = ""
	}

	return copy
}

func (p Profile) Reference() string {
	if name := strings.TrimSpace(p.Name); name != "" {
		return name
	}

	return strings.TrimSpace(p.ID)
}

func ValidateCreateRequest(request CreateRequest) error {
	profile := Profile{
		SiteID:   request.SiteID,
		Name:     request.Name,
		Protocol: request.Protocol,
		SNMP:     CloneSNMPProfile(request.SNMP),
		SSH:      CloneSSHProfile(request.SSH),
		WinRM:    CloneWinRMProfile(request.WinRM),
	}

	return ValidateProfile(profile)
}

func ValidateProfile(profile Profile) error {
	if strings.TrimSpace(profile.SiteID) == "" {
		return fmt.Errorf("credential profile site id is required")
	}

	if strings.TrimSpace(profile.Name) == "" {
		return fmt.Errorf("credential profile name is required")
	}

	protocol := NormalizeProtocol(profile.Protocol)
	if protocol == "" {
		return fmt.Errorf("credential profile protocol is required")
	}

	switch protocol {
	case ProtocolSNMP:
		if err := ValidateSNMPProfile(profile.SNMP); err != nil {
			return err
		}
	case ProtocolSSH:
		if err := ValidateSSHProfile(profile.SSH); err != nil {
			return err
		}
	case ProtocolWinRM:
		if err := ValidateWinRMProfile(profile.WinRM); err != nil {
			return err
		}
	default:
		return fmt.Errorf("credential profile protocol %q is invalid", profile.Protocol)
	}

	return nil
}

func ValidateSNMPProfile(profile *SNMPProfile) error {
	if profile == nil {
		return fmt.Errorf("credential profile snmp settings are required")
	}

	if profile.Port < 0 || profile.Port > 65535 {
		return fmt.Errorf("credential profile snmp port is invalid")
	}

	version := NormalizeSNMPVersion(profile.Version)
	switch version {
	case SNMPVersion2c:
		if strings.TrimSpace(profile.Community) == "" {
			return fmt.Errorf("credential profile snmp community is required for version %q", version)
		}
	case SNMPVersion3:
		if strings.TrimSpace(profile.Username) == "" {
			return fmt.Errorf("credential profile snmp username is required for version %q", version)
		}

		authProtocol := NormalizeSNMPAuthProtocol(profile.AuthProtocol)
		privacyProtocol := NormalizeSNMPPrivacyProtocol(profile.PrivacyProtocol)
		hasAuth := authProtocol != "" || strings.TrimSpace(profile.AuthPassword) != ""
		hasPrivacy := privacyProtocol != "" || strings.TrimSpace(profile.PrivacyPassword) != ""

		if hasPrivacy && !hasAuth {
			return fmt.Errorf("credential profile snmp privacy requires authentication settings")
		}

		if hasAuth {
			if authProtocol == "" {
				return fmt.Errorf("credential profile snmp auth protocol is required when auth password is set")
			}

			if strings.TrimSpace(profile.AuthPassword) == "" {
				return fmt.Errorf("credential profile snmp auth password is required when auth protocol is set")
			}
		}

		if hasPrivacy {
			if privacyProtocol == "" {
				return fmt.Errorf("credential profile snmp privacy protocol is required when privacy password is set")
			}

			if strings.TrimSpace(profile.PrivacyPassword) == "" {
				return fmt.Errorf("credential profile snmp privacy password is required when privacy protocol is set")
			}
		}

		if authProtocol != "" {
			switch authProtocol {
			case "md5", "sha", "sha224", "sha256", "sha384", "sha512":
			default:
				return fmt.Errorf("credential profile snmp auth protocol %q is invalid", profile.AuthProtocol)
			}
		}

		if privacyProtocol != "" {
			switch privacyProtocol {
			case "des", "aes", "aes192", "aes256":
			default:
				return fmt.Errorf("credential profile snmp privacy protocol %q is invalid", profile.PrivacyProtocol)
			}
		}
	default:
		return fmt.Errorf("credential profile snmp version %q is invalid", profile.Version)
	}

	return nil
}

func ValidateSSHProfile(profile *SSHProfile) error {
	if profile == nil {
		return fmt.Errorf("credential profile ssh settings are required")
	}

	if profile.Port < 0 || profile.Port > 65535 {
		return fmt.Errorf("credential profile ssh port is invalid")
	}

	if strings.TrimSpace(profile.Username) == "" {
		return fmt.Errorf("credential profile ssh username is required")
	}

	hasPassword := strings.TrimSpace(profile.Password) != ""
	hasPrivateKey := strings.TrimSpace(profile.PrivateKey) != ""

	switch {
	case hasPassword && hasPrivateKey:
		return fmt.Errorf("credential profile ssh auth must use either password or private key")
	case !hasPassword && !hasPrivateKey:
		return fmt.Errorf("credential profile ssh password or private key is required")
	case hasPrivateKey:
		if _, err := ParseSSHPrivateKey(profile.PrivateKey, profile.Passphrase); err != nil {
			return err
		}
	}

	return nil
}

func ValidateWinRMProfile(profile *WinRMProfile) error {
	if profile == nil {
		return fmt.Errorf("credential profile winrm settings are required")
	}

	if profile.Port < 0 || profile.Port > 65535 {
		return fmt.Errorf("credential profile winrm port is invalid")
	}

	if strings.TrimSpace(profile.Username) == "" {
		return fmt.Errorf("credential profile winrm username is required")
	}

	if strings.TrimSpace(profile.Password) == "" {
		return fmt.Errorf("credential profile winrm password is required")
	}

	if !WinRMUsesHTTPS(profile) && !profile.AllowHTTP {
		return fmt.Errorf("credential profile winrm http requires allow_http")
	}

	return nil
}

func ParseSSHPrivateKey(privateKey string, passphrase string) (cryptossh.Signer, error) {
	keyBytes := []byte(strings.TrimSpace(privateKey))
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("credential profile ssh private key is invalid")
	}

	signer, err := cryptossh.ParsePrivateKey(keyBytes)
	if err == nil {
		return signer, nil
	}

	var missingPassphrase *cryptossh.PassphraseMissingError
	if errors.As(err, &missingPassphrase) {
		if passphrase == "" {
			return nil, fmt.Errorf("credential profile ssh private key passphrase is required")
		}

		signer, err = cryptossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("credential profile ssh private key is invalid")
		}

		return signer, nil
	}

	if passphrase != "" {
		signer, err = cryptossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
		if err == nil {
			return signer, nil
		}
	}

	return nil, fmt.Errorf("credential profile ssh private key is invalid")
}
