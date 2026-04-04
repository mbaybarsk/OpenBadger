package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

const (
	ObservationType    = "passive.pcap_sighting"
	defaultSnapLen     = 1600
	defaultReadTimeout = 500 * time.Millisecond
	defaultWindow      = 10 * time.Second
)

type SourceConfig struct {
	Interface   string
	FilePath    string
	SnapLen     int32
	Promiscuous bool
	ReadTimeout time.Duration
}

type EmitterConfig struct {
	SiteID  string
	NodeID  string
	Name    string
	Version string
}

type PacketMetadata struct {
	Timestamp time.Time
	Length    int
	Protocols []string
	Endpoints []EndpointMetadata
}

type EndpointMetadata struct {
	MAC          string
	IPs          []string
	VLANs        []int
	DHCPHostname string
	MDNSNames    []string
	NBNSName     string
}

type WindowProcessor struct {
	openSource func(SourceConfig) (packetSource, error)
	now        func() time.Time
}

type ObservationAggregator struct {
	entries map[string]*aggregateEntry
}

type aggregateEntry struct {
	firstSeen    time.Time
	lastSeen     time.Time
	packetCount  int64
	byteCount    int64
	protocols    map[string]struct{}
	macs         map[string]struct{}
	ips          map[string]struct{}
	vlans        map[int]struct{}
	mdnsNames    map[string]struct{}
	dhcpHostname string
	nbnsName     string
}

type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	Close()
}

type offlineSource struct {
	reader *pcapgo.Reader
	file   *os.File
}

func NewWindowProcessor() *WindowProcessor {
	return &WindowProcessor{
		openSource: openSource,
		now:        time.Now,
	}
}

func (p *WindowProcessor) CaptureWindow(ctx context.Context, sourceConfig SourceConfig, emitter EmitterConfig, window time.Duration) ([]observations.Observation, error) {
	if p == nil {
		p = NewWindowProcessor()
	}

	source, err := p.openSource(sourceConfig)
	if err != nil {
		return nil, err
	}
	defer source.Close()

	aggregator := NewObservationAggregator()
	deadline := time.Time{}
	if strings.TrimSpace(sourceConfig.FilePath) == "" {
		if window <= 0 {
			window = defaultWindow
		}
		deadline = p.now().Add(window)
	}

	for {
		if ctx.Err() != nil {
			break
		}

		if !deadline.IsZero() && !p.now().Before(deadline) {
			break
		}

		data, captureInfo, err := source.ReadPacketData()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				return aggregator.Observations(emitter), nil
			case isTimeoutError(err):
				continue
			default:
				return nil, fmt.Errorf("read packet data: %w", err)
			}
		}

		packet := gopacket.NewPacket(data, source.LinkType(), gopacket.Default)
		metadata := ParsePacket(packet, captureInfo)
		if len(metadata.Endpoints) == 0 {
			continue
		}

		aggregator.Add(metadata)
	}

	return aggregator.Observations(emitter), nil
}

func NewObservationAggregator() *ObservationAggregator {
	return &ObservationAggregator{entries: make(map[string]*aggregateEntry)}
}

func (a *ObservationAggregator) Add(metadata PacketMetadata) {
	if a == nil {
		return
	}

	for _, endpoint := range metadata.Endpoints {
		key := endpointKey(endpoint)
		if key == "" {
			continue
		}

		entry, ok := a.entries[key]
		if !ok {
			entry = &aggregateEntry{
				protocols: make(map[string]struct{}),
				macs:      make(map[string]struct{}),
				ips:       make(map[string]struct{}),
				vlans:     make(map[int]struct{}),
				mdnsNames: make(map[string]struct{}),
			}
			a.entries[key] = entry
		}

		if entry.firstSeen.IsZero() || metadata.Timestamp.Before(entry.firstSeen) {
			entry.firstSeen = metadata.Timestamp.UTC()
		}

		if metadata.Timestamp.After(entry.lastSeen) {
			entry.lastSeen = metadata.Timestamp.UTC()
		}

		entry.packetCount++
		entry.byteCount += int64(metadata.Length)

		if endpoint.MAC != "" {
			entry.macs[endpoint.MAC] = struct{}{}
		}

		for _, ipAddress := range endpoint.IPs {
			entry.ips[ipAddress] = struct{}{}
		}

		for _, vlanID := range endpoint.VLANs {
			entry.vlans[vlanID] = struct{}{}
		}

		for _, protocol := range metadata.Protocols {
			entry.protocols[protocol] = struct{}{}
		}

		if entry.dhcpHostname == "" && endpoint.DHCPHostname != "" {
			entry.dhcpHostname = endpoint.DHCPHostname
		}

		if entry.nbnsName == "" && endpoint.NBNSName != "" {
			entry.nbnsName = endpoint.NBNSName
		}

		for _, name := range endpoint.MDNSNames {
			entry.mdnsNames[name] = struct{}{}
		}
	}
}

func (a *ObservationAggregator) Observations(emitter EmitterConfig) []observations.Observation {
	if a == nil || len(a.entries) == 0 {
		return nil
	}

	keys := make([]string, 0, len(a.entries))
	for key := range a.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	results := make([]observations.Observation, 0, len(keys))
	for _, key := range keys {
		entry := a.entries[key]
		if entry == nil {
			continue
		}

		firstSeen := entry.firstSeen
		lastSeen := entry.lastSeen
		if firstSeen.IsZero() {
			firstSeen = lastSeen
		}

		observation := observations.Observation{
			SchemaVersion: observations.SchemaVersion,
			ObservationID: uuid.NewString(),
			Type:          ObservationType,
			Scope:         "sighting",
			SiteID:        strings.TrimSpace(emitter.SiteID),
			Emitter: &observations.Emitter{
				Kind:       "sensor",
				ID:         strings.TrimSpace(emitter.NodeID),
				Name:       strings.TrimSpace(emitter.Name),
				Version:    strings.TrimSpace(emitter.Version),
				Capability: "pcap",
			},
			ObservedAt: lastSeen,
			Facts: map[string]any{
				"protocols": mapKeysSorted(entry.protocols),
			},
			Evidence: &observations.Evidence{
				Confidence:     entry.confidence(),
				SourceProtocol: "pcap",
				FirstSeen:      timePointer(firstSeen),
				LastSeen:       timePointer(lastSeen),
				PacketCount:    entry.packetCount,
				ByteCount:      entry.byteCount,
			},
		}

		macAddresses := mapKeysSorted(entry.macs)
		if len(macAddresses) > 0 {
			observation.Identifiers = &observations.Identifiers{MACAddresses: macAddresses}
		}

		ipAddresses := mapKeysSorted(entry.ips)
		vlanIDs := mapIntKeysSorted(entry.vlans)
		if len(ipAddresses) > 0 || len(vlanIDs) > 0 {
			observation.Addresses = &observations.Addresses{
				IPAddresses: ipAddresses,
				VLANIDs:     vlanIDs,
			}
		}

		if entry.dhcpHostname != "" {
			observation.Facts["dhcp_hostname"] = entry.dhcpHostname
		}

		if len(entry.mdnsNames) > 0 {
			observation.Facts["mdns_names"] = mapKeysSorted(entry.mdnsNames)
		}

		if entry.nbnsName != "" {
			observation.Facts["nbns_name"] = entry.nbnsName
		}

		results = append(results, observation)
	}

	return results
}

func ParsePacket(packet gopacket.Packet, captureInfo gopacket.CaptureInfo) PacketMetadata {
	builder := newPacketMetadataBuilder(captureInfo)
	vlanIDs := extractVLANIDs(packet, captureInfo)

	var ethernet *layers.Ethernet
	if layer := packet.Layer(layers.LayerTypeEthernet); layer != nil {
		if parsed, ok := layer.(*layers.Ethernet); ok {
			ethernet = parsed
		}
	}

	srcMAC := ""
	dstMAC := ""
	if ethernet != nil {
		srcMAC = canonicalMAC(ethernet.SrcMAC)
		dstMAC = canonicalMAC(ethernet.DstMAC)
	}

	srcIP := ""
	dstIP := ""
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		if parsed, ok := layer.(*layers.IPv4); ok {
			builder.addProtocol("ipv4")
			srcIP = canonicalIP(parsed.SrcIP)
			dstIP = canonicalIP(parsed.DstIP)
			if shouldTrackEndpoint(srcMAC, parsed.SrcIP) {
				builder.mergeEndpoint(EndpointMetadata{MAC: srcMAC, IPs: compactStrings(srcIP), VLANs: vlanIDs})
			}
			if dstMAC != "" && shouldTrackEndpoint(dstMAC, parsed.DstIP) {
				builder.mergeEndpoint(EndpointMetadata{MAC: dstMAC, IPs: compactStrings(dstIP), VLANs: vlanIDs})
			}
		}
	}

	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		if parsed, ok := layer.(*layers.IPv6); ok {
			builder.addProtocol("ipv6")
			if srcIP == "" {
				srcIP = canonicalIP(parsed.SrcIP)
			}
			if dstIP == "" {
				dstIP = canonicalIP(parsed.DstIP)
			}
			if shouldTrackEndpoint(srcMAC, parsed.SrcIP) {
				builder.mergeEndpoint(EndpointMetadata{MAC: srcMAC, IPs: compactStrings(canonicalIP(parsed.SrcIP)), VLANs: vlanIDs})
			}
			if dstMAC != "" && shouldTrackEndpoint(dstMAC, parsed.DstIP) {
				builder.mergeEndpoint(EndpointMetadata{MAC: dstMAC, IPs: compactStrings(canonicalIP(parsed.DstIP)), VLANs: vlanIDs})
			}
		}
	}

	if layer := packet.Layer(layers.LayerTypeARP); layer != nil {
		if parsed, ok := layer.(*layers.ARP); ok {
			builder.addProtocol("arp")
			builder.mergeEndpoint(EndpointMetadata{
				MAC:   canonicalMAC(net.HardwareAddr(parsed.SourceHwAddress)),
				IPs:   compactStrings(canonicalIP(net.IP(parsed.SourceProtAddress))),
				VLANs: vlanIDs,
			})

			targetMAC := canonicalMAC(net.HardwareAddr(parsed.DstHwAddress))
			if targetMAC != "" {
				builder.mergeEndpoint(EndpointMetadata{
					MAC:   targetMAC,
					IPs:   compactStrings(canonicalIP(net.IP(parsed.DstProtAddress))),
					VLANs: vlanIDs,
				})
			}
		}
	}

	if layer := packet.Layer(layers.LayerTypeDHCPv4); layer != nil {
		if parsed, ok := layer.(*layers.DHCPv4); ok {
			builder.addProtocol("dhcp")
			builder.mergeEndpoint(EndpointMetadata{
				MAC:          firstNonEmpty(canonicalMAC(parsed.ClientHWAddr), srcMAC),
				IPs:          compactStrings(canonicalIP(parsed.ClientIP), canonicalIP(parsed.YourClientIP), srcIP),
				VLANs:        vlanIDs,
				DHCPHostname: dhcpHostname(parsed),
			})
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			if udp.SrcPort == 5353 || udp.DstPort == 5353 {
				dns := decodeDNSPayload(udp.Payload)
				names := extractMDNSNames(dns)
				if len(names) > 0 {
					builder.addProtocol("mdns")
					builder.mergeEndpoint(EndpointMetadata{
						MAC:       srcMAC,
						IPs:       compactStrings(srcIP),
						VLANs:     vlanIDs,
						MDNSNames: names,
					})
				}
			}

			if udp.SrcPort == 137 || udp.DstPort == 137 {
				if name := extractNBNSName(udp.Payload); name != "" {
					builder.addProtocol("nbns")
					builder.mergeEndpoint(EndpointMetadata{
						MAC:      srcMAC,
						IPs:      compactStrings(srcIP),
						VLANs:    vlanIDs,
						NBNSName: name,
					})
				}
			}
		}
	}

	return builder.metadata()
}

func (s *offlineSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.reader.ReadPacketData()
}

func (s *offlineSource) LinkType() layers.LinkType {
	return s.reader.LinkType()
}

func (s *offlineSource) Close() {
	if s != nil && s.file != nil {
		_ = s.file.Close()
	}
}

func openSource(cfg SourceConfig) (packetSource, error) {
	if filePath := strings.TrimSpace(cfg.FilePath); filePath != "" {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("open pcap file: %w", err)
		}

		reader, err := pcapgo.NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("create pcap reader: %w", err)
		}

		return &offlineSource{reader: reader, file: file}, nil
	}

	device := strings.TrimSpace(cfg.Interface)
	if device == "" {
		return nil, fmt.Errorf("pcap interface or file path is required")
	}

	return openLiveSource(cfg)
}

type packetMetadataBuilder struct {
	timestamp time.Time
	length    int
	protocols map[string]struct{}
	endpoints map[string]*EndpointMetadata
}

func newPacketMetadataBuilder(captureInfo gopacket.CaptureInfo) *packetMetadataBuilder {
	return &packetMetadataBuilder{
		timestamp: captureInfo.Timestamp.UTC(),
		length:    captureInfo.Length,
		protocols: make(map[string]struct{}),
		endpoints: make(map[string]*EndpointMetadata),
	}
}

func (b *packetMetadataBuilder) addProtocol(value string) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return
	}

	b.protocols[value] = struct{}{}
}

func (b *packetMetadataBuilder) mergeEndpoint(endpoint EndpointMetadata) {
	endpoint = normalizeEndpoint(endpoint)
	key := endpointKey(endpoint)
	if key == "" {
		return
	}

	existing, ok := b.endpoints[key]
	if !ok {
		copyEndpoint := endpoint
		b.endpoints[key] = &copyEndpoint
		return
	}

	if existing.MAC == "" {
		existing.MAC = endpoint.MAC
	}

	existing.IPs = mergeStringSlices(existing.IPs, endpoint.IPs)
	existing.VLANs = mergeIntSlices(existing.VLANs, endpoint.VLANs)
	existing.MDNSNames = mergeStringSlices(existing.MDNSNames, endpoint.MDNSNames)
	if existing.DHCPHostname == "" {
		existing.DHCPHostname = endpoint.DHCPHostname
	}
	if existing.NBNSName == "" {
		existing.NBNSName = endpoint.NBNSName
	}
}

func (b *packetMetadataBuilder) metadata() PacketMetadata {
	protocols := mapKeysSorted(b.protocols)
	keys := make([]string, 0, len(b.endpoints))
	for key := range b.endpoints {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	endpoints := make([]EndpointMetadata, 0, len(keys))
	for _, key := range keys {
		endpoints = append(endpoints, *b.endpoints[key])
	}

	return PacketMetadata{
		Timestamp: b.timestamp,
		Length:    b.length,
		Protocols: protocols,
		Endpoints: endpoints,
	}
}

func extractVLANIDs(packet gopacket.Packet, captureInfo gopacket.CaptureInfo) []int {
	var vlanIDs []int
	for _, layer := range packet.Layers() {
		dot1q, ok := layer.(*layers.Dot1Q)
		if !ok {
			continue
		}

		vlanIDs = append(vlanIDs, int(dot1q.VLANIdentifier))
	}

	vlanIDs = append(vlanIDs, extractAncillaryVLANs(captureInfo)...)

	return uniqueSortedInts(vlanIDs)
}

func dhcpHostname(packet *layers.DHCPv4) string {
	if packet == nil {
		return ""
	}

	for _, option := range packet.Options {
		if option.Type == layers.DHCPOptHostname {
			return normalizeName(string(option.Data))
		}
	}

	return ""
}

func decodeDNSPayload(payload []byte) *layers.DNS {
	if len(payload) == 0 {
		return nil
	}

	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}

	return &dns
}

func extractMDNSNames(dns *layers.DNS) []string {
	if dns == nil {
		return nil
	}

	names := make([]string, 0, len(dns.Answers)+len(dns.Additionals)+len(dns.Authorities)+len(dns.Questions))
	appendRecordNames := func(records []layers.DNSResourceRecord) {
		for _, record := range records {
			names = append(names, normalizeName(string(record.Name)))
			names = append(names, normalizeName(string(record.PTR)))
			names = append(names, normalizeName(string(record.CNAME)))
		}
	}

	appendRecordNames(dns.Answers)
	appendRecordNames(dns.Additionals)
	appendRecordNames(dns.Authorities)

	if len(names) == 0 {
		for _, question := range dns.Questions {
			names = append(names, normalizeName(string(question.Name)))
		}
	}

	return uniqueSortedStrings(names)
}

func extractNBNSName(payload []byte) string {
	if len(payload) < 12+1+32+1 {
		return ""
	}

	start := 12
	labelLength := int(payload[start])
	if labelLength != 32 || len(payload) < start+1+labelLength {
		return ""
	}

	decoded := make([]byte, 16)
	encoded := payload[start+1 : start+1+labelLength]
	for i := 0; i < len(decoded); i++ {
		high := encoded[i*2]
		low := encoded[i*2+1]
		if high < 'A' || high > 'P' || low < 'A' || low > 'P' {
			return ""
		}

		decoded[i] = ((high - 'A') << 4) | (low - 'A')
	}

	return normalizeName(string(decoded[:15]))
}

func normalizeEndpoint(endpoint EndpointMetadata) EndpointMetadata {
	endpoint.MAC = canonicalMAC(parseHardwareAddr(endpoint.MAC))
	endpoint.IPs = uniqueSortedStrings(endpoint.IPs)
	endpoint.VLANs = uniqueSortedInts(endpoint.VLANs)
	endpoint.DHCPHostname = normalizeName(endpoint.DHCPHostname)
	endpoint.MDNSNames = uniqueSortedStrings(endpoint.MDNSNames)
	endpoint.NBNSName = normalizeName(endpoint.NBNSName)
	return endpoint
}

func endpointKey(endpoint EndpointMetadata) string {
	if endpoint.MAC != "" {
		return "mac:" + endpoint.MAC
	}

	if len(endpoint.IPs) > 0 {
		return "ip:" + endpoint.IPs[0]
	}

	return ""
}

func shouldTrackEndpoint(mac string, ip net.IP) bool {
	if strings.TrimSpace(mac) != "" {
		return true
	}

	if ip == nil {
		return false
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return !(ipv4.IsUnspecified() || ipv4.IsMulticast() || ipv4.Equal(net.IPv4bcast))
	}

	return !(ip.IsUnspecified() || ip.IsMulticast())
}

func (e *aggregateEntry) confidence() float64 {
	confidence := 0.35
	if len(e.macs) > 0 {
		confidence += 0.20
	}
	if len(e.ips) > 0 {
		confidence += 0.15
	}
	if e.dhcpHostname != "" || e.nbnsName != "" || len(e.mdnsNames) > 0 {
		confidence += 0.15
	}
	if len(e.vlans) > 0 {
		confidence += 0.05
	}
	if len(e.protocols) > 1 {
		confidence += 0.05
	}
	if confidence > 0.90 {
		confidence = 0.90
	}
	return confidence
}

func canonicalMAC(addr net.HardwareAddr) string {
	if len(addr) == 0 {
		return ""
	}

	if len(addr) == 6 {
		allZero := true
		for _, value := range addr {
			if value != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return ""
		}
	}

	if len(addr) > 0 && addr[0]&1 == 1 {
		return ""
	}

	return strings.ToLower(addr.String())
}

func canonicalIP(ip net.IP) string {
	if ip == nil {
		return ""
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		if ipv4.IsUnspecified() || ipv4.IsMulticast() || ipv4.Equal(net.IPv4bcast) {
			return ""
		}
		return ipv4.String()
	}

	if ip.IsUnspecified() || ip.IsMulticast() {
		return ""
	}

	return ip.String()
}

func normalizeName(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimRight(value, ".")))
	value = strings.Trim(value, "\x00 ")
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func compactStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

func mergeStringSlices(base []string, extra []string) []string {
	return uniqueSortedStrings(append(append([]string(nil), base...), extra...))
}

func mergeIntSlices(base []int, extra []int) []int {
	return uniqueSortedInts(append(append([]int(nil), base...), extra...))
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeName(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	sort.Strings(result)
	if len(result) == 0 {
		return nil
	}
	return result
}

func uniqueSortedInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[int]struct{}, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	sort.Ints(result)
	if len(result) == 0 {
		return nil
	}
	return result
}

func mapKeysSorted(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func mapIntKeysSorted(values map[int]struct{}) []int {
	if len(values) == 0 {
		return nil
	}

	result := make([]int, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copyValue := value.UTC()
	return &copyValue
}

func parseHardwareAddr(value string) net.HardwareAddr {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	addr, err := net.ParseMAC(value)
	if err != nil {
		return nil
	}

	return addr
}
