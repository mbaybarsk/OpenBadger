package targets

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

const DefaultMaxExpandedTargets = 65536

type Range struct {
	CIDR       string   `json:"cidr"`
	Exclusions []string `json:"exclusions,omitempty"`
}

type ExpandedTarget struct {
	Input string
	IP    string
}

type Expander struct {
	MaxTargets int
}

func (e Expander) Expand(ranges []Range) ([]ExpandedTarget, error) {
	if len(ranges) == 0 {
		return nil, nil
	}

	maxTargets := e.MaxTargets
	if maxTargets <= 0 {
		maxTargets = DefaultMaxExpandedTargets
	}

	seen := make(map[string]struct{})
	expanded := make([]ExpandedTarget, 0)
	for i, targetRange := range ranges {
		prefix, err := parseCIDR(targetRange.CIDR)
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: %w", i, err)
		}

		if _, err := usableAddressCount(prefix, maxTargets); err != nil {
			return nil, fmt.Errorf("targets[%d]: %w", i, err)
		}

		exclusions, err := parseExclusions(targetRange.Exclusions)
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: %w", i, err)
		}

		current := prefix.Addr()
		last := lastAddr(prefix)
		for prefix.Contains(current) {
			if shouldSkipHost(prefix, current, last) || exclusions.Contains(current) {
				if current == last {
					break
				}
				current = current.Next()
				continue
			}

			ip := current.String()
			if _, exists := seen[ip]; !exists {
				if len(expanded) >= maxTargets {
					return nil, fmt.Errorf("expanded target count exceeds limit %d", maxTargets)
				}

				seen[ip] = struct{}{}
				expanded = append(expanded, ExpandedTarget{Input: ip, IP: ip})
			}

			if current == last {
				break
			}

			current = current.Next()
		}

	}

	return expanded, nil
}

func parseCIDR(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("cidr is required")
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse cidr %q: %w", value, err)
	}

	return prefix.Masked(), nil
}

func usableAddressCount(prefix netip.Prefix, maxTargets int) (int, error) {
	bitLength := 128
	if prefix.Addr().Is4() {
		bitLength = 32
	}

	hostBits := bitLength - prefix.Bits()
	if hostBits < 0 {
		return 0, fmt.Errorf("cidr %q is invalid", prefix.String())
	}

	if hostBits > 16 {
		return 0, fmt.Errorf("cidr %q expands beyond limit %d", prefix.String(), maxTargets)
	}

	count := 1 << hostBits
	if prefix.Addr().Is4() && prefix.Bits() <= 30 {
		count -= 2
	}

	if count < 0 {
		count = 0
	}

	if count > maxTargets {
		return 0, fmt.Errorf("cidr %q expands beyond limit %d", prefix.String(), maxTargets)
	}

	return count, nil
}

func shouldSkipHost(prefix netip.Prefix, current netip.Addr, last netip.Addr) bool {
	return prefix.Addr().Is4() && prefix.Bits() <= 30 && (current == prefix.Addr() || current == last)
}

type exclusionSet struct {
	exact    map[string]struct{}
	prefixes []netip.Prefix
}

func parseExclusions(values []string) (exclusionSet, error) {
	set := exclusionSet{exact: make(map[string]struct{})}
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return exclusionSet{}, fmt.Errorf("parse exclusion %d %q: %w", i, value, err)
			}

			set.prefixes = append(set.prefixes, prefix.Masked())
			continue
		}

		addr, err := netip.ParseAddr(value)
		if err != nil {
			return exclusionSet{}, fmt.Errorf("parse exclusion %d %q: %w", i, value, err)
		}

		set.exact[addr.String()] = struct{}{}
	}

	return set, nil
}

func (s exclusionSet) Contains(addr netip.Addr) bool {
	if _, ok := s.exact[addr.String()]; ok {
		return true
	}

	for _, prefix := range s.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if addr.Is4() {
		bytes := addr.As4()
		value := binary.BigEndian.Uint32(bytes[:])
		hostBits := uint(32 - prefix.Bits())
		if hostBits == 0 {
			return addr
		}

		value |= (uint32(1) << hostBits) - 1
		var last [4]byte
		binary.BigEndian.PutUint32(last[:], value)
		return netip.AddrFrom4(last)
	}

	bytes := addr.As16()
	for bit := prefix.Bits(); bit < 128; bit++ {
		byteIndex := bit / 8
		bitIndex := 7 - (bit % 8)
		bytes[byteIndex] |= 1 << bitIndex
	}

	return netip.AddrFrom16(bytes)
}
