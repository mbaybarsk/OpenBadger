package winrm

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
		return nil, fmt.Errorf("winrm observation site id is required")
	}

	if strings.TrimSpace(context.NodeID) == "" {
		return nil, fmt.Errorf("winrm observation node id is required")
	}

	if addr, err := netip.ParseAddr(strings.TrimSpace(context.TargetIP)); err != nil || !addr.IsValid() {
		return nil, fmt.Errorf("winrm observation target ip is required")
	}

	if context.ObservedAt.IsZero() {
		return nil, fmt.Errorf("winrm observation observed_at is required")
	}

	observedAt := context.ObservedAt.UTC().Truncate(time.Second)
	targetIP := strings.TrimSpace(context.TargetIP)
	targetInput := strings.TrimSpace(context.TargetInput)
	if targetInput == "" {
		targetInput = targetIP
	}

	hostnameRaw := strings.TrimSpace(result.Hostname)
	hostname := normalizeHostname(hostnameRaw)
	domainRaw := strings.TrimSpace(result.Domain)
	fqdn := normalizeFQDN(hostnameRaw, domainRaw)
	uuidValue := normalizeUUID(result.SystemUUID)
	addresses := normalizeIPAddresses(targetIP, result.NetworkAddresses)

	identifiers := &observations.Identifiers{}
	if hostname != "" {
		identifiers.Hostnames = []string{hostname}
	}
	if fqdn != "" {
		identifiers.FQDN = fqdn
	}
	if serialNumber := strings.TrimSpace(result.SerialNumber); serialNumber != "" {
		identifiers.SerialNumber = serialNumber
	}
	if uuidValue != "" {
		identifiers.SystemUUID = uuidValue
		identifiers.BIOSUUID = uuidValue
	}

	facts := map[string]any{}
	if hostnameRaw != "" {
		facts["hostname"] = hostnameRaw
	} else if hostname != "" {
		facts["hostname"] = hostname
	}
	if domainRaw != "" {
		facts["domain"] = domainRaw
	}
	if value := strings.TrimSpace(result.OSName); value != "" {
		facts["os_name"] = value
	}
	if value := strings.TrimSpace(result.OSVersion); value != "" {
		facts["os_version"] = value
	}
	if value := strings.TrimSpace(result.BuildNumber); value != "" {
		facts["build_number"] = value
	}
	if value := strings.TrimSpace(result.Manufacturer); value != "" {
		facts["manufacturer"] = value
	}
	if value := strings.TrimSpace(result.Model); value != "" {
		facts["model"] = value
	}

	port := context.Port
	if port <= 0 {
		port = credentials.DefaultWinRMPort(0, true)
	}

	observation := observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          "winrm.windows_host",
		Scope:         "asset",
		SiteID:        strings.TrimSpace(context.SiteID),
		JobID:         strings.TrimSpace(context.JobID),
		Emitter: &observations.Emitter{
			Kind:       strings.TrimSpace(context.NodeKind),
			ID:         strings.TrimSpace(context.NodeID),
			Name:       strings.TrimSpace(context.NodeName),
			Version:    strings.TrimSpace(context.Version),
			Capability: "winrm",
		},
		ObservedAt: observedAt,
		Target: &observations.Target{
			Input:    targetInput,
			IP:       targetIP,
			Protocol: "winrm",
			Port:     port,
		},
		Identifiers: identifiers,
		Addresses: &observations.Addresses{
			IPAddresses: addresses,
		},
		Facts: facts,
		Evidence: &observations.Evidence{
			Confidence:        confidenceForResult(result),
			SourceProtocol:    "winrm",
			CredentialProfile: strings.TrimSpace(context.CredentialProfile),
		},
	}

	return []observations.Observation{observation}, nil
}

func normalizeHostname(value string) string {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	if value == "" {
		return ""
	}

	if index := strings.IndexByte(value, '.'); index > 0 {
		return value[:index]
	}

	return value
}

func normalizeFQDN(hostname string, domain string) string {
	hostname = strings.ToLower(strings.Trim(strings.TrimSpace(hostname), "."))
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))

	if hostname == "" {
		return ""
	}

	if strings.Contains(hostname, ".") {
		return hostname
	}

	if domain == "" || !strings.Contains(domain, ".") {
		return ""
	}

	return hostname + "." + domain
}

func normalizeUUID(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "{")
	value = strings.TrimSuffix(value, "}")
	if value == "" {
		return ""
	}

	parsed, err := uuid.Parse(value)
	if err != nil {
		return ""
	}

	if parsed == uuid.Nil {
		return ""
	}

	return strings.ToLower(parsed.String())
}

func normalizeIPAddresses(targetIP string, values []string) []string {
	result := make([]string, 0, len(values)+1)
	seen := map[string]struct{}{}

	appendAddress := func(value string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.IsValid() {
			return
		}

		canonical := addr.String()
		if _, ok := seen[canonical]; ok {
			return
		}

		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}

	appendAddress(targetIP)
	for _, value := range values {
		appendAddress(value)
	}

	return result
}

func confidenceForResult(result Result) float64 {
	hasSerial := strings.TrimSpace(result.SerialNumber) != ""
	hasUUID := normalizeUUID(result.SystemUUID) != ""

	switch {
	case hasSerial && hasUUID:
		return 0.98
	case hasSerial || hasUUID:
		return 0.96
	default:
		return 0.90
	}
}
