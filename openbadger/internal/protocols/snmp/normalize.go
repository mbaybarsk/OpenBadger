package snmp

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

type SystemData struct {
	SysName     string
	SysDescr    string
	SysObjectID string
	UptimeTicks uint64
	EngineID    string
}

type InterfaceData struct {
	Index       int
	Name        string
	Alias       string
	Description string
	AdminStatus string
	OperStatus  string
	SpeedBPS    uint64
	MACAddress  string
}

type ARPEntry struct {
	InterfaceIndex int
	ObservedIP     string
	ObservedMAC    string
}

type FDBEntry struct {
	BridgePort     int
	InterfaceIndex int
	ObservedMAC    string
	VLANID         int
}

type Result struct {
	System     SystemData
	Interfaces []InterfaceData
	ARPEntries []ARPEntry
	FDBEntries []FDBEntry
}

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

type DeviceInfo struct {
	Vendor    string
	Model     string
	OSName    string
	OSVersion string
}

var (
	ciscoIOSXEPattern   = regexp.MustCompile(`(?i)IOS XE Software.*?Version\s+([^,\s]+)`)
	ciscoIOSPattern     = regexp.MustCompile(`(?i)Cisco IOS Software.*?Version\s+([^,\s]+)`)
	junosPattern        = regexp.MustCompile(`(?i)JUNOS .*\[([^\]]+)\]`)
	routerOSPattern     = regexp.MustCompile(`(?i)RouterOS\s+([^\s,]+)`)
	ciscoModelPattern   = regexp.MustCompile(`\b(C\d{3,4}[A-Z0-9-]*)\b`)
	juniperModelPattern = regexp.MustCompile(`\b(EX\d{4}[A-Z0-9-]*)\b`)
)

var exactObjectIDMap = map[string]DeviceInfo{
	"1.3.6.1.4.1.9.1.2695":        {Vendor: "Cisco", Model: "C9300", OSName: "IOS-XE"},
	"1.3.6.1.4.1.2636.1.1.1.2.71": {Vendor: "Juniper", Model: "EX4300", OSName: "Junos"},
}

var enterpriseVendorMap = map[string]string{
	"9":     "Cisco",
	"11":    "HP",
	"8072":  "Net-SNMP",
	"11863": "Aruba",
	"14179": "MikroTik",
	"2011":  "Huawei",
	"2636":  "Juniper",
	"41112": "Ubiquiti",
}

func NormalizeObservations(context NormalizeContext, result Result) ([]observations.Observation, error) {
	if strings.TrimSpace(context.SiteID) == "" {
		return nil, fmt.Errorf("snmp observation site id is required")
	}

	if strings.TrimSpace(context.NodeID) == "" {
		return nil, fmt.Errorf("snmp observation node id is required")
	}

	if addr, err := netip.ParseAddr(strings.TrimSpace(context.TargetIP)); err != nil || !addr.IsValid() {
		return nil, fmt.Errorf("snmp observation target ip is required")
	}

	if context.ObservedAt.IsZero() {
		return nil, fmt.Errorf("snmp observation observed_at is required")
	}

	observedAt := context.ObservedAt.UTC().Truncate(time.Second)
	targetIP := strings.TrimSpace(context.TargetIP)
	targetInput := strings.TrimSpace(context.TargetInput)
	if targetInput == "" {
		targetInput = targetIP
	}

	baseIdentifiers := &observations.Identifiers{}
	if hostname := normalizeHostname(result.System.SysName); hostname != "" {
		baseIdentifiers.Hostnames = []string{hostname}
	}
	if engineID := normalizeHexString(result.System.EngineID); engineID != "" {
		baseIdentifiers.SNMPEngineID = engineID
	}

	deviceInfo := LookupDeviceInfo(result.System.SysObjectID, result.System.SysDescr)
	observationsOut := make([]observations.Observation, 0, 1+len(result.Interfaces)+len(result.ARPEntries)+len(result.FDBEntries))

	systemFacts := make(map[string]any)
	if value := strings.TrimSpace(result.System.SysName); value != "" {
		systemFacts["sys_name"] = value
	}
	if value := strings.TrimSpace(result.System.SysDescr); value != "" {
		systemFacts["sys_descr"] = value
	}
	if value := normalizeOID(result.System.SysObjectID); value != "" {
		systemFacts["sys_object_id"] = value
	}
	if deviceInfo.Vendor != "" {
		systemFacts["vendor"] = deviceInfo.Vendor
	}
	if deviceInfo.Model != "" {
		systemFacts["model"] = deviceInfo.Model
	}
	if deviceInfo.OSName != "" {
		systemFacts["os_name"] = deviceInfo.OSName
	}
	if deviceInfo.OSVersion != "" {
		systemFacts["os_version"] = deviceInfo.OSVersion
	}
	if result.System.UptimeTicks > 0 {
		systemFacts["uptime_ticks"] = result.System.UptimeTicks
	}

	observationsOut = append(observationsOut, buildObservation(observationSpec{
		Type:        "snmp.system",
		Scope:       "asset",
		Confidence:  0.98,
		Context:     context,
		ObservedAt:  observedAt,
		TargetInput: targetInput,
		TargetIP:    targetIP,
		Identifiers: cloneIdentifiers(baseIdentifiers),
		Addresses:   &observations.Addresses{IPAddresses: []string{targetIP}},
		Facts:       systemFacts,
	}))

	for _, iface := range result.Interfaces {
		facts := make(map[string]any)
		if value := strings.TrimSpace(iface.Name); value != "" {
			facts["name"] = value
		}
		if value := strings.TrimSpace(iface.Alias); value != "" {
			facts["alias"] = value
		}
		if value := strings.TrimSpace(iface.Description); value != "" {
			facts["description"] = value
		}
		if value := normalizeState(iface.AdminStatus); value != "" {
			facts["admin_status"] = value
		}
		if value := normalizeState(iface.OperStatus); value != "" {
			facts["oper_status"] = value
		}
		if iface.SpeedBPS > 0 {
			facts["speed_bps"] = iface.SpeedBPS
		}
		if value := normalizeMAC(iface.MACAddress); value != "" {
			facts["mac_address"] = value
		}

		addresses := &observations.Addresses{IPAddresses: []string{targetIP}}
		if value := strings.TrimSpace(iface.Name); value != "" {
			addresses.InterfaceName = value
		} else if value := strings.TrimSpace(iface.Description); value != "" {
			addresses.InterfaceName = value
		}
		if iface.Index > 0 {
			addresses.InterfaceIndex = iface.Index
		}

		observationsOut = append(observationsOut, buildObservation(observationSpec{
			Type:        "snmp.interface",
			Scope:       "asset",
			Confidence:  0.95,
			Context:     context,
			ObservedAt:  observedAt,
			TargetInput: targetInput,
			TargetIP:    targetIP,
			Identifiers: cloneIdentifiers(baseIdentifiers),
			Addresses:   addresses,
			Facts:       facts,
		}))
	}

	for _, entry := range result.ARPEntries {
		mac := normalizeMAC(entry.ObservedMAC)
		ip := strings.TrimSpace(entry.ObservedIP)
		if mac == "" || ip == "" {
			continue
		}

		facts := map[string]any{
			"observed_ip":  ip,
			"observed_mac": mac,
		}
		if entry.InterfaceIndex > 0 {
			facts["interface_index"] = entry.InterfaceIndex
		}

		relations := []map[string]any{{
			"type": "ip_mac_mapping",
			"peer_identifiers": map[string]any{
				"mac_addresses": []string{mac},
			},
			"peer_addresses": map[string]any{
				"ip_addresses": []string{ip},
			},
		}}

		observationsOut = append(observationsOut, buildObservation(observationSpec{
			Type:        "snmp.arp_entry",
			Scope:       "relationship",
			Confidence:  0.75,
			Context:     context,
			ObservedAt:  observedAt,
			TargetInput: targetInput,
			TargetIP:    targetIP,
			Identifiers: cloneIdentifiers(baseIdentifiers),
			Facts:       facts,
			Relations:   relations,
		}))
	}

	for _, entry := range result.FDBEntries {
		mac := normalizeMAC(entry.ObservedMAC)
		if mac == "" {
			continue
		}

		facts := map[string]any{
			"observed_mac": mac,
		}
		if entry.BridgePort > 0 {
			facts["bridge_port"] = entry.BridgePort
		}
		if entry.InterfaceIndex > 0 {
			facts["interface_index"] = entry.InterfaceIndex
		}
		if entry.VLANID > 0 {
			facts["vlan_id"] = entry.VLANID
		}

		addresses := &observations.Addresses{}
		if entry.InterfaceIndex > 0 {
			addresses.InterfaceIndex = entry.InterfaceIndex
		}
		if entry.VLANID > 0 {
			addresses.VLANIDs = []int{entry.VLANID}
		}

		relations := []map[string]any{{
			"type": "switch_learned_mac",
			"peer_identifiers": map[string]any{
				"mac_addresses": []string{mac},
			},
		}}

		observationsOut = append(observationsOut, buildObservation(observationSpec{
			Type:        "snmp.fdb_entry",
			Scope:       "relationship",
			Confidence:  0.72,
			Context:     context,
			ObservedAt:  observedAt,
			TargetInput: targetInput,
			TargetIP:    targetIP,
			Identifiers: cloneIdentifiers(baseIdentifiers),
			Addresses:   addresses,
			Facts:       facts,
			Relations:   relations,
		}))
	}

	return observationsOut, nil
}

type observationSpec struct {
	Type        string
	Scope       string
	Confidence  float64
	Context     NormalizeContext
	ObservedAt  time.Time
	TargetInput string
	TargetIP    string
	Identifiers *observations.Identifiers
	Addresses   *observations.Addresses
	Facts       map[string]any
	Relations   []map[string]any
}

func buildObservation(spec observationSpec) observations.Observation {
	port := spec.Context.Port
	if port <= 0 {
		port = 161
	}

	return observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          spec.Type,
		Scope:         spec.Scope,
		SiteID:        strings.TrimSpace(spec.Context.SiteID),
		JobID:         strings.TrimSpace(spec.Context.JobID),
		Emitter: &observations.Emitter{
			Kind:       strings.TrimSpace(spec.Context.NodeKind),
			ID:         strings.TrimSpace(spec.Context.NodeID),
			Name:       strings.TrimSpace(spec.Context.NodeName),
			Version:    strings.TrimSpace(spec.Context.Version),
			Capability: "snmp",
		},
		ObservedAt: spec.ObservedAt,
		Target: &observations.Target{
			Input:    spec.TargetInput,
			IP:       spec.TargetIP,
			Protocol: "snmp",
			Port:     port,
		},
		Identifiers: spec.Identifiers,
		Addresses:   spec.Addresses,
		Facts:       ensureFacts(spec.Facts),
		Relations:   spec.Relations,
		Evidence: &observations.Evidence{
			Confidence:        spec.Confidence,
			SourceProtocol:    "snmp",
			CredentialProfile: strings.TrimSpace(spec.Context.CredentialProfile),
		},
	}
}

func ensureFacts(facts map[string]any) map[string]any {
	if facts == nil {
		return map[string]any{}
	}

	return facts
}

func cloneIdentifiers(value *observations.Identifiers) *observations.Identifiers {
	if value == nil {
		return nil
	}

	copy := *value
	copy.Hostnames = append([]string(nil), value.Hostnames...)
	copy.MACAddresses = append([]string(nil), value.MACAddresses...)
	copy.SSHHostKeyFingerprints = append([]string(nil), value.SSHHostKeyFingerprints...)
	return &copy
}

func LookupDeviceInfo(sysObjectID string, sysDescr string) DeviceInfo {
	normalizedObjectID := normalizeOID(sysObjectID)
	info := exactObjectIDMap[normalizedObjectID]
	if info.Vendor == "" {
		info.Vendor = vendorFromObjectID(normalizedObjectID)
	}

	descr := strings.TrimSpace(sysDescr)
	if info.OSName == "" || info.OSVersion == "" {
		parsedOS := parseOSInfo(descr)
		if info.OSName == "" {
			info.OSName = parsedOS.OSName
		}
		if info.OSVersion == "" {
			info.OSVersion = parsedOS.OSVersion
		}
	}

	if info.Model == "" {
		info.Model = inferModel(descr)
	}

	return info
}

func vendorFromObjectID(value string) string {
	parts := oidInts(value)
	if len(parts) < 7 {
		return ""
	}

	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == 1 && parts[i+1] == 4 && i+3 < len(parts) && parts[i+2] == 1 {
			return enterpriseVendorMap[strconv.Itoa(parts[i+3])]
		}
	}

	return ""
}

func parseOSInfo(sysDescr string) DeviceInfo {
	if matches := ciscoIOSXEPattern.FindStringSubmatch(sysDescr); len(matches) == 2 {
		return DeviceInfo{OSName: "IOS-XE", OSVersion: matches[1]}
	}

	if matches := ciscoIOSPattern.FindStringSubmatch(sysDescr); len(matches) == 2 {
		return DeviceInfo{OSName: "IOS", OSVersion: matches[1]}
	}

	if matches := junosPattern.FindStringSubmatch(sysDescr); len(matches) == 2 {
		return DeviceInfo{OSName: "Junos", OSVersion: matches[1]}
	}

	if matches := routerOSPattern.FindStringSubmatch(sysDescr); len(matches) == 2 {
		return DeviceInfo{OSName: "RouterOS", OSVersion: matches[1]}
	}

	return DeviceInfo{}
}

func inferModel(sysDescr string) string {
	if matches := ciscoModelPattern.FindStringSubmatch(sysDescr); len(matches) == 2 {
		return matches[1]
	}

	if matches := juniperModelPattern.FindStringSubmatch(sysDescr); len(matches) == 2 {
		return matches[1]
	}

	return ""
}

func normalizeHostname(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeHexString(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, ":", "")
	value = strings.ReplaceAll(value, "-", "")
	return value
}

func normalizeOID(value string) string {
	return strings.Trim(strings.TrimSpace(value), ".")
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if parsed, err := net.ParseMAC(value); err == nil {
		normalized := strings.ToLower(parsed.String())
		if normalized == "00:00:00:00:00:00" {
			return ""
		}
		return normalized
	}

	replacer := strings.NewReplacer("-", "", ":", "", ".", "", " ", "")
	compact := replacer.Replace(strings.ToLower(value))
	if len(compact)%2 != 0 || compact == "000000000000" {
		return ""
	}

	bytes := make([]byte, 0, len(compact)/2)
	for i := 0; i+1 < len(compact); i += 2 {
		part, err := strconv.ParseUint(compact[i:i+2], 16, 8)
		if err != nil {
			return ""
		}
		bytes = append(bytes, byte(part))
	}

	normalized := strings.ToLower(net.HardwareAddr(bytes).String())
	if normalized == "00:00:00:00:00:00" {
		return ""
	}

	return normalized
}

func normalizeState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "up", "1":
		return "up"
	case "down", "2":
		return "down"
	case "unknown":
		return "unknown"
	default:
		return "unknown"
	}
}

func oidInts(value string) []int {
	trimmed := normalizeOID(value)
	if trimmed == "" {
		return nil
	}

	parts := strings.Split(trimmed, ".")
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return nil
		}
		result = append(result, parsed)
	}

	return result
}

func oidSuffix(baseOID string, fullOID string) ([]int, error) {
	base := oidInts(baseOID)
	full := oidInts(fullOID)
	if len(base) == 0 || len(full) <= len(base) {
		return nil, fmt.Errorf("oid suffix is invalid")
	}

	for i := range base {
		if base[i] != full[i] {
			return nil, fmt.Errorf("oid suffix is invalid")
		}
	}

	return full[len(base):], nil
}

func parseInterfaceIndex(baseOID string, fullOID string) (int, error) {
	suffix, err := oidSuffix(baseOID, fullOID)
	if err != nil || len(suffix) != 1 {
		return 0, fmt.Errorf("interface index oid is invalid")
	}

	return suffix[0], nil
}

func parseARPEntryOID(baseOID string, fullOID string) (int, string, error) {
	suffix, err := oidSuffix(baseOID, fullOID)
	if err != nil || len(suffix) != 5 {
		return 0, "", fmt.Errorf("arp entry oid is invalid")
	}

	ip, ok := netip.AddrFromSlice([]byte{byte(suffix[1]), byte(suffix[2]), byte(suffix[3]), byte(suffix[4])})
	if !ok {
		return 0, "", fmt.Errorf("arp entry oid is invalid")
	}

	return suffix[0], ip.String(), nil
}

func parseFDBEntryOID(baseOID string, fullOID string) (string, error) {
	suffix, err := oidSuffix(baseOID, fullOID)
	if err != nil || len(suffix) != 6 {
		return "", fmt.Errorf("fdb entry oid is invalid")
	}

	return normalizeMAC(net.HardwareAddr([]byte{byte(suffix[0]), byte(suffix[1]), byte(suffix[2]), byte(suffix[3]), byte(suffix[4]), byte(suffix[5])}).String()), nil
}

func parseQBridgeFDBEntryOID(baseOID string, fullOID string) (int, string, error) {
	suffix, err := oidSuffix(baseOID, fullOID)
	if err != nil || len(suffix) != 7 {
		return 0, "", fmt.Errorf("qbridge fdb entry oid is invalid")
	}

	mac := normalizeMAC(net.HardwareAddr([]byte{byte(suffix[1]), byte(suffix[2]), byte(suffix[3]), byte(suffix[4]), byte(suffix[5]), byte(suffix[6])}).String())
	return suffix[0], mac, nil
}
