package targets

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Record struct {
	ID         string    `json:"id"`
	SiteID     string    `json:"site_id"`
	Name       string    `json:"name"`
	CIDR       string    `json:"cidr"`
	Exclusions []string  `json:"exclusions,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type CreateRequest struct {
	SiteID     string   `json:"site_id"`
	Name       string   `json:"name"`
	CIDR       string   `json:"cidr"`
	Exclusions []string `json:"exclusions,omitempty"`
}

type DebugCreateResponse struct {
	TargetRange Record `json:"target_range"`
}

func NormalizeCIDR(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("cidr is required")
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", fmt.Errorf("cidr %q is invalid: %w", value, err)
	}

	return prefix.Masked().String(), nil
}

func NormalizeExclusions(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		var normalizedValue string
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("exclusions[%d] %q is invalid: %w", i, value, err)
			}

			normalizedValue = prefix.Masked().String()
		} else {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return nil, fmt.Errorf("exclusions[%d] %q is invalid: %w", i, value, err)
			}

			normalizedValue = addr.String()
		}

		if _, exists := seen[normalizedValue]; exists {
			continue
		}

		seen[normalizedValue] = struct{}{}
		normalized = append(normalized, normalizedValue)
	}

	return normalized, nil
}
