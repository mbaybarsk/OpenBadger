package nodes

import (
	"errors"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("node not found")
	ErrConflict = errors.New("node conflict")
)

type Kind string

const (
	KindCollector Kind = "collector"
	KindSensor    Kind = "sensor"
)

type Record struct {
	ID              string
	SiteID          string
	Kind            Kind
	Name            string
	Version         string
	Capabilities    []string
	HealthStatus    string
	LastHeartbeatAt *time.Time
	AuthTokenHash   string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type CreateParams struct {
	SiteID          string
	Kind            Kind
	Name            string
	Version         string
	Capabilities    []string
	HealthStatus    string
	LastHeartbeatAt *time.Time
	AuthTokenHash   string
}

type HeartbeatParams struct {
	NodeID          string
	Name            string
	Version         string
	Capabilities    []string
	HealthStatus    string
	LastHeartbeatAt time.Time
}

func NormalizeKind(value string) Kind {
	return Kind(strings.ToLower(strings.TrimSpace(value)))
}

func ValidateKind(kind Kind) bool {
	switch NormalizeKind(string(kind)) {
	case KindCollector, KindSensor:
		return true
	default:
		return false
	}
}

func NormalizeCapabilities(capabilities []string) []string {
	if len(capabilities) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(capabilities))
	normalized := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if capability == "" {
			continue
		}

		if _, exists := seen[capability]; exists {
			continue
		}

		seen[capability] = struct{}{}
		normalized = append(normalized, capability)
	}

	if len(normalized) == 0 {
		return nil
	}

	for i := 0; i < len(normalized)-1; i++ {
		for j := i + 1; j < len(normalized); j++ {
			if normalized[j] < normalized[i] {
				normalized[i], normalized[j] = normalized[j], normalized[i]
			}
		}
	}

	return normalized
}

func DefaultCapabilities(kind Kind) []string {
	switch NormalizeKind(string(kind)) {
	case KindCollector:
		return []string{"icmp", "snmp", "ssh", "winrm"}
	case KindSensor:
		return []string{"flow", "pcap"}
	default:
		return nil
	}
}
