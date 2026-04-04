package ssh

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mbaybarsk/openbadger/internal/credentials"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

type NormalizeContext struct {
	SiteID            string
	JobID             string
	NodeKind          string
	NodeID            string
	NodeName          string
	Version           string
	TargetInput       string
	TargetIP          string
	Port              int
	ObservedAt        time.Time
	CredentialProfile string
}

func NormalizeObservations(context NormalizeContext, result Result) ([]observations.Observation, error) {
	if strings.TrimSpace(context.SiteID) == "" {
		return nil, fmt.Errorf("ssh observation site id is required")
	}

	if strings.TrimSpace(context.NodeID) == "" {
		return nil, fmt.Errorf("ssh observation node id is required")
	}

	if addr, err := netip.ParseAddr(strings.TrimSpace(context.TargetIP)); err != nil || !addr.IsValid() {
		return nil, fmt.Errorf("ssh observation target ip is required")
	}

	if context.ObservedAt.IsZero() {
		return nil, fmt.Errorf("ssh observation observed_at is required")
	}

	observedAt := context.ObservedAt.UTC().Truncate(time.Second)
	targetIP := strings.TrimSpace(context.TargetIP)
	targetInput := strings.TrimSpace(context.TargetInput)
	if targetInput == "" {
		targetInput = targetIP
	}

	hostname := normalizeHostname(result.Hostname)
	fqdn := normalizeFQDN(result.FQDN)
	if hostname == "" && fqdn != "" {
		hostname = hostnameFromFQDN(fqdn)
	}

	identifiers := &observations.Identifiers{}
	if hostname != "" {
		identifiers.Hostnames = []string{hostname}
	}
	if fqdn != "" {
		identifiers.FQDN = fqdn
	}
	if fingerprint := strings.TrimSpace(result.HostKeyFingerprint); fingerprint != "" {
		identifiers.SSHHostKeyFingerprints = []string{fingerprint}
	}
	if machineID := normalizeMachineID(result.MachineID); machineID != "" {
		identifiers.MachineID = machineID
	}

	facts := map[string]any{}
	if hostname != "" {
		facts["hostname"] = hostname
	}
	if fqdn != "" {
		facts["fqdn"] = fqdn
	}
	if value := strings.TrimSpace(result.OSRelease.Name); value != "" {
		facts["os_name"] = value
	}
	if value := firstNonEmpty([]string{strings.TrimSpace(result.OSRelease.Version), strings.TrimSpace(result.OSRelease.VersionID)}); value != "" {
		facts["os_version"] = value
	}
	if value := strings.TrimSpace(result.OSRelease.PrettyName); value != "" {
		facts["os_pretty_name"] = value
	}
	if value := strings.ToLower(strings.TrimSpace(result.OSRelease.ID)); value != "" {
		facts["os_id"] = value
	}
	if value := strings.ToLower(strings.TrimSpace(result.OSRelease.IDLike)); value != "" {
		facts["os_id_like"] = value
	}
	if value := strings.TrimSpace(result.OSRelease.VersionID); value != "" {
		facts["os_version_id"] = value
	}
	if value := strings.TrimSpace(result.KernelVersion); value != "" {
		facts["kernel_version"] = value
	}
	if value := strings.TrimSpace(result.Architecture); value != "" {
		facts["architecture"] = value
	}

	port := context.Port
	if port <= 0 {
		port = credentials.DefaultSSHPort(0)
	}

	observation := observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          "ssh.host",
		Scope:         "asset",
		SiteID:        strings.TrimSpace(context.SiteID),
		JobID:         strings.TrimSpace(context.JobID),
		Emitter: &observations.Emitter{
			Kind:       strings.TrimSpace(context.NodeKind),
			ID:         strings.TrimSpace(context.NodeID),
			Name:       strings.TrimSpace(context.NodeName),
			Version:    strings.TrimSpace(context.Version),
			Capability: "ssh",
		},
		ObservedAt: observedAt,
		Target: &observations.Target{
			Input:    targetInput,
			IP:       targetIP,
			Protocol: "ssh",
			Port:     port,
		},
		Identifiers: identifiers,
		Addresses: &observations.Addresses{
			IPAddresses: []string{targetIP},
		},
		Facts: facts,
		Evidence: &observations.Evidence{
			Confidence:        confidenceForResult(result),
			SourceProtocol:    "ssh",
			CredentialProfile: strings.TrimSpace(context.CredentialProfile),
		},
	}

	return []observations.Observation{observation}, nil
}

func normalizeHostname(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeFQDN(value string) string {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	if value == "" || !strings.Contains(value, ".") {
		return ""
	}

	return value
}

func normalizeMachineID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "")
	if len(value) != 32 {
		return ""
	}

	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return ""
		}
	}

	if value == "00000000000000000000000000000000" {
		return ""
	}

	return value
}

func confidenceForResult(result Result) float64 {
	hasFingerprint := strings.TrimSpace(result.HostKeyFingerprint) != ""
	hasMachineID := normalizeMachineID(result.MachineID) != ""

	switch {
	case hasFingerprint && hasMachineID:
		return 0.99
	case hasFingerprint:
		return 0.97
	case hasMachineID:
		return 0.96
	default:
		return 0.90
	}
}
