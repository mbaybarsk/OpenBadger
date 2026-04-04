package jobs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

const defaultICMPTimeout = time.Second

const defaultSNMPTimeout = 2 * time.Second

const defaultSSHTimeout = 5 * time.Second

const defaultWinRMTimeout = 5 * time.Second

type ICMPScanTarget struct {
	CIDR       string   `json:"cidr"`
	Exclusions []string `json:"exclusions,omitempty"`
}

type ICMPScanPayload struct {
	Targets   []ICMPScanTarget `json:"targets"`
	TimeoutMS int              `json:"timeout_ms,omitempty"`
}

type SNMPScanTarget struct {
	CIDR       string   `json:"cidr"`
	Exclusions []string `json:"exclusions,omitempty"`
}

type SNMPScanPayload struct {
	Targets             []SNMPScanTarget     `json:"targets"`
	Port                int                  `json:"port,omitempty"`
	TimeoutMS           int                  `json:"timeout_ms,omitempty"`
	RetryCount          int                  `json:"retry_count,omitempty"`
	CredentialProfileID string               `json:"credential_profile_id,omitempty"`
	CredentialProfile   *credentials.Profile `json:"credential_profile,omitempty"`
}

type SSHScanTarget struct {
	CIDR       string   `json:"cidr"`
	Exclusions []string `json:"exclusions,omitempty"`
}

type SSHScanPayload struct {
	Targets             []SSHScanTarget      `json:"targets"`
	Port                int                  `json:"port,omitempty"`
	TimeoutMS           int                  `json:"timeout_ms,omitempty"`
	CredentialProfileID string               `json:"credential_profile_id,omitempty"`
	CredentialProfile   *credentials.Profile `json:"credential_profile,omitempty"`
}

type WinRMScanTarget struct {
	CIDR       string   `json:"cidr"`
	Exclusions []string `json:"exclusions,omitempty"`
}

type WinRMScanPayload struct {
	Targets             []WinRMScanTarget    `json:"targets"`
	Port                int                  `json:"port,omitempty"`
	TimeoutMS           int                  `json:"timeout_ms,omitempty"`
	CredentialProfileID string               `json:"credential_profile_id,omitempty"`
	CredentialProfile   *credentials.Profile `json:"credential_profile,omitempty"`
}

func ParseICMPScanPayload(raw json.RawMessage) (ICMPScanPayload, error) {
	var payload ICMPScanPayload
	if len(bytes.TrimSpace(raw)) == 0 {
		return ICMPScanPayload{}, fmt.Errorf("icmp job payload is required")
	}

	if err := json.Unmarshal(raw, &payload); err != nil {
		return ICMPScanPayload{}, fmt.Errorf("decode icmp job payload: %w", err)
	}

	if len(payload.Targets) == 0 {
		return ICMPScanPayload{}, fmt.Errorf("icmp job payload targets are required")
	}

	for i, target := range payload.Targets {
		if strings.TrimSpace(target.CIDR) == "" {
			return ICMPScanPayload{}, fmt.Errorf("icmp job payload targets[%d].cidr is required", i)
		}
	}

	if payload.TimeoutMS < 0 {
		return ICMPScanPayload{}, fmt.Errorf("icmp job payload timeout_ms is invalid")
	}

	return payload, nil
}

func (p ICMPScanPayload) Timeout() time.Duration {
	if p.TimeoutMS <= 0 {
		return defaultICMPTimeout
	}

	return time.Duration(p.TimeoutMS) * time.Millisecond
}

func (p ICMPScanPayload) TargetRanges() []targets.Range {
	if len(p.Targets) == 0 {
		return nil
	}

	ranges := make([]targets.Range, 0, len(p.Targets))
	for _, target := range p.Targets {
		ranges = append(ranges, targets.Range{
			CIDR:       target.CIDR,
			Exclusions: append([]string(nil), target.Exclusions...),
		})
	}

	return ranges
}

func ParseSNMPScanPayload(raw json.RawMessage) (SNMPScanPayload, error) {
	var payload SNMPScanPayload
	if len(bytes.TrimSpace(raw)) == 0 {
		return SNMPScanPayload{}, fmt.Errorf("snmp job payload is required")
	}

	if err := json.Unmarshal(raw, &payload); err != nil {
		return SNMPScanPayload{}, fmt.Errorf("decode snmp job payload: %w", err)
	}

	if len(payload.Targets) == 0 {
		return SNMPScanPayload{}, fmt.Errorf("snmp job payload targets are required")
	}

	for i, target := range payload.Targets {
		if strings.TrimSpace(target.CIDR) == "" {
			return SNMPScanPayload{}, fmt.Errorf("snmp job payload targets[%d].cidr is required", i)
		}
	}

	if payload.Port < 0 || payload.Port > 65535 {
		return SNMPScanPayload{}, fmt.Errorf("snmp job payload port is invalid")
	}

	if payload.TimeoutMS < 0 {
		return SNMPScanPayload{}, fmt.Errorf("snmp job payload timeout_ms is invalid")
	}

	if payload.RetryCount < 0 {
		return SNMPScanPayload{}, fmt.Errorf("snmp job payload retry_count is invalid")
	}

	if payload.CredentialProfile == nil || payload.CredentialProfile.SNMP == nil {
		return SNMPScanPayload{}, fmt.Errorf("snmp job payload credential profile is required")
	}

	if protocol := strings.TrimSpace(payload.CredentialProfile.Protocol); protocol != "" && credentials.NormalizeProtocol(protocol) != credentials.ProtocolSNMP {
		return SNMPScanPayload{}, fmt.Errorf("snmp job payload credential profile protocol %q is invalid", protocol)
	}

	payload.CredentialProfile.Protocol = credentials.ProtocolSNMP
	if err := credentials.ValidateSNMPProfile(payload.CredentialProfile.SNMP); err != nil {
		return SNMPScanPayload{}, err
	}

	return payload, nil
}

func (p SNMPScanPayload) Timeout() time.Duration {
	if p.TimeoutMS <= 0 {
		return defaultSNMPTimeout
	}

	return time.Duration(p.TimeoutMS) * time.Millisecond
}

func (p SNMPScanPayload) TargetRanges() []targets.Range {
	if len(p.Targets) == 0 {
		return nil
	}

	ranges := make([]targets.Range, 0, len(p.Targets))
	for _, target := range p.Targets {
		ranges = append(ranges, targets.Range{
			CIDR:       target.CIDR,
			Exclusions: append([]string(nil), target.Exclusions...),
		})
	}

	return ranges
}

func (p SNMPScanPayload) Credential() credentials.SNMPProfile {
	if p.CredentialProfile == nil || p.CredentialProfile.SNMP == nil {
		return credentials.SNMPProfile{}
	}

	copy := credentials.CloneSNMPProfile(p.CredentialProfile.SNMP)
	if copy == nil {
		return credentials.SNMPProfile{}
	}

	return *copy
}

func (p SNMPScanPayload) CredentialReference() string {
	if p.CredentialProfile == nil {
		return strings.TrimSpace(p.CredentialProfileID)
	}

	if reference := p.CredentialProfile.Reference(); reference != "" {
		return reference
	}

	return strings.TrimSpace(p.CredentialProfileID)
}

func (p SNMPScanPayload) EffectivePort() int {
	if p.Port > 0 {
		return p.Port
	}

	if p.CredentialProfile != nil && p.CredentialProfile.SNMP != nil && p.CredentialProfile.SNMP.Port > 0 {
		return p.CredentialProfile.SNMP.Port
	}

	return credentials.DefaultSNMPPort(0)
}

func ParseSSHScanPayload(raw json.RawMessage) (SSHScanPayload, error) {
	var payload SSHScanPayload
	if len(bytes.TrimSpace(raw)) == 0 {
		return SSHScanPayload{}, fmt.Errorf("ssh job payload is required")
	}

	if err := json.Unmarshal(raw, &payload); err != nil {
		return SSHScanPayload{}, fmt.Errorf("decode ssh job payload: %w", err)
	}

	if len(payload.Targets) == 0 {
		return SSHScanPayload{}, fmt.Errorf("ssh job payload targets are required")
	}

	for i, target := range payload.Targets {
		if strings.TrimSpace(target.CIDR) == "" {
			return SSHScanPayload{}, fmt.Errorf("ssh job payload targets[%d].cidr is required", i)
		}
	}

	if payload.Port < 0 || payload.Port > 65535 {
		return SSHScanPayload{}, fmt.Errorf("ssh job payload port is invalid")
	}

	if payload.TimeoutMS < 0 {
		return SSHScanPayload{}, fmt.Errorf("ssh job payload timeout_ms is invalid")
	}

	if payload.CredentialProfile == nil || payload.CredentialProfile.SSH == nil {
		return SSHScanPayload{}, fmt.Errorf("ssh job payload credential profile is required")
	}

	if protocol := strings.TrimSpace(payload.CredentialProfile.Protocol); protocol != "" && credentials.NormalizeProtocol(protocol) != credentials.ProtocolSSH {
		return SSHScanPayload{}, fmt.Errorf("ssh job payload credential profile protocol %q is invalid", protocol)
	}

	payload.CredentialProfile.Protocol = credentials.ProtocolSSH
	if err := credentials.ValidateSSHProfile(payload.CredentialProfile.SSH); err != nil {
		return SSHScanPayload{}, err
	}

	return payload, nil
}

func (p SSHScanPayload) Timeout() time.Duration {
	if p.TimeoutMS <= 0 {
		return defaultSSHTimeout
	}

	return time.Duration(p.TimeoutMS) * time.Millisecond
}

func (p SSHScanPayload) TargetRanges() []targets.Range {
	if len(p.Targets) == 0 {
		return nil
	}

	ranges := make([]targets.Range, 0, len(p.Targets))
	for _, target := range p.Targets {
		ranges = append(ranges, targets.Range{
			CIDR:       target.CIDR,
			Exclusions: append([]string(nil), target.Exclusions...),
		})
	}

	return ranges
}

func (p SSHScanPayload) Credential() credentials.SSHProfile {
	if p.CredentialProfile == nil || p.CredentialProfile.SSH == nil {
		return credentials.SSHProfile{}
	}

	copy := credentials.CloneSSHProfile(p.CredentialProfile.SSH)
	if copy == nil {
		return credentials.SSHProfile{}
	}

	return *copy
}

func (p SSHScanPayload) CredentialReference() string {
	if p.CredentialProfile == nil {
		return strings.TrimSpace(p.CredentialProfileID)
	}

	if reference := p.CredentialProfile.Reference(); reference != "" {
		return reference
	}

	return strings.TrimSpace(p.CredentialProfileID)
}

func (p SSHScanPayload) EffectivePort() int {
	if p.Port > 0 {
		return p.Port
	}

	if p.CredentialProfile != nil && p.CredentialProfile.SSH != nil && p.CredentialProfile.SSH.Port > 0 {
		return p.CredentialProfile.SSH.Port
	}

	return credentials.DefaultSSHPort(0)
}

func ParseWinRMScanPayload(raw json.RawMessage) (WinRMScanPayload, error) {
	var payload WinRMScanPayload
	if len(bytes.TrimSpace(raw)) == 0 {
		return WinRMScanPayload{}, fmt.Errorf("winrm job payload is required")
	}

	if err := json.Unmarshal(raw, &payload); err != nil {
		return WinRMScanPayload{}, fmt.Errorf("decode winrm job payload: %w", err)
	}

	if len(payload.Targets) == 0 {
		return WinRMScanPayload{}, fmt.Errorf("winrm job payload targets are required")
	}

	for i, target := range payload.Targets {
		if strings.TrimSpace(target.CIDR) == "" {
			return WinRMScanPayload{}, fmt.Errorf("winrm job payload targets[%d].cidr is required", i)
		}
	}

	if payload.Port < 0 || payload.Port > 65535 {
		return WinRMScanPayload{}, fmt.Errorf("winrm job payload port is invalid")
	}

	if payload.TimeoutMS < 0 {
		return WinRMScanPayload{}, fmt.Errorf("winrm job payload timeout_ms is invalid")
	}

	if payload.CredentialProfile == nil || payload.CredentialProfile.WinRM == nil {
		return WinRMScanPayload{}, fmt.Errorf("winrm job payload credential profile is required")
	}

	if protocol := strings.TrimSpace(payload.CredentialProfile.Protocol); protocol != "" && credentials.NormalizeProtocol(protocol) != credentials.ProtocolWinRM {
		return WinRMScanPayload{}, fmt.Errorf("winrm job payload credential profile protocol %q is invalid", protocol)
	}

	payload.CredentialProfile.Protocol = credentials.ProtocolWinRM
	if err := credentials.ValidateWinRMProfile(payload.CredentialProfile.WinRM); err != nil {
		return WinRMScanPayload{}, err
	}

	return payload, nil
}

func (p WinRMScanPayload) Timeout() time.Duration {
	if p.TimeoutMS <= 0 {
		return defaultWinRMTimeout
	}

	return time.Duration(p.TimeoutMS) * time.Millisecond
}

func (p WinRMScanPayload) TargetRanges() []targets.Range {
	if len(p.Targets) == 0 {
		return nil
	}

	ranges := make([]targets.Range, 0, len(p.Targets))
	for _, target := range p.Targets {
		ranges = append(ranges, targets.Range{
			CIDR:       target.CIDR,
			Exclusions: append([]string(nil), target.Exclusions...),
		})
	}

	return ranges
}

func (p WinRMScanPayload) Credential() credentials.WinRMProfile {
	if p.CredentialProfile == nil || p.CredentialProfile.WinRM == nil {
		return credentials.WinRMProfile{}
	}

	copy := credentials.CloneWinRMProfile(p.CredentialProfile.WinRM)
	if copy == nil {
		return credentials.WinRMProfile{}
	}

	return *copy
}

func (p WinRMScanPayload) CredentialReference() string {
	if p.CredentialProfile == nil {
		return strings.TrimSpace(p.CredentialProfileID)
	}

	if reference := p.CredentialProfile.Reference(); reference != "" {
		return reference
	}

	return strings.TrimSpace(p.CredentialProfileID)
}

func (p WinRMScanPayload) UsesHTTPS() bool {
	if p.CredentialProfile == nil {
		return true
	}

	return credentials.WinRMUsesHTTPS(p.CredentialProfile.WinRM)
}

func (p WinRMScanPayload) EffectivePort() int {
	if p.Port > 0 {
		return p.Port
	}

	if p.CredentialProfile != nil && p.CredentialProfile.WinRM != nil && p.CredentialProfile.WinRM.Port > 0 {
		return p.CredentialProfile.WinRM.Port
	}

	return credentials.DefaultWinRMPort(0, p.UsesHTTPS())
}
