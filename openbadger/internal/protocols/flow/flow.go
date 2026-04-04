package flow

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

const ObservationType = "flow.sighting"

type Datagram struct {
	ExporterAddress string
	ReceivedAt      time.Time
	Payload         []byte
}

type Record struct {
	ExporterAddress string
	ObservedAt      time.Time
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Protocol        string
	ByteCount       uint64
	PacketCount     uint64
}

type EmitterConfig struct {
	SiteID  string
	NodeID  string
	Name    string
	Version string
}

type Decoder interface {
	Decode(datagram Datagram) ([]Record, error)
}

type TemplateAdapter struct {
	mu       sync.Mutex
	sessions map[sessionKey]*templateSession
}

type sessionKey struct {
	Version  uint16
	Exporter string
	Domain   uint32
}

type templateSession struct {
	templates map[uint16]flowTemplate
}

type flowTemplate struct {
	ID            uint16
	Fields        []templateField
	RecordLength  int
	VariableField bool
}

type templateField struct {
	Type   uint16
	Length uint16
}

type Aggregator struct {
	entries map[string]*aggregateEntry
}

type aggregateEntry struct {
	exporterAddress string
	endpointIP      string
	firstSeen       time.Time
	lastSeen        time.Time
	byteCount       uint64
	packetCount     uint64
	flowCount       uint64
	protocols       map[string]uint64
	ports           map[uint16]uint64
	peers           map[string]uint64
}

func NewTemplateAdapter() *TemplateAdapter {
	return &TemplateAdapter{sessions: make(map[sessionKey]*templateSession)}
}

func NewAggregator() *Aggregator {
	return &Aggregator{entries: make(map[string]*aggregateEntry)}
}

func (a *TemplateAdapter) Decode(datagram Datagram) ([]Record, error) {
	if a == nil {
		a = NewTemplateAdapter()
	}

	if len(datagram.Payload) < 2 {
		return nil, fmt.Errorf("flow datagram is too short")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	version := binary.BigEndian.Uint16(datagram.Payload[:2])
	switch version {
	case 9:
		return a.decodeNetFlowV9(datagram)
	case 10:
		return a.decodeIPFIX(datagram)
	default:
		return nil, fmt.Errorf("unsupported flow version %d", version)
	}
}

func (a *TemplateAdapter) decodeNetFlowV9(datagram Datagram) ([]Record, error) {
	payload := datagram.Payload
	if len(payload) < 20 {
		return nil, fmt.Errorf("netflow v9 datagram is truncated")
	}

	session := a.ensureSession(sessionKey{
		Version:  9,
		Exporter: normalizeAddress(datagram.ExporterAddress),
		Domain:   binary.BigEndian.Uint32(payload[16:20]),
	})

	var records []Record
	for offset := 20; offset+4 <= len(payload); {
		setID := binary.BigEndian.Uint16(payload[offset : offset+2])
		setLength := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		if setLength < 4 || offset+setLength > len(payload) {
			return nil, fmt.Errorf("netflow v9 flowset length is invalid")
		}

		body := payload[offset+4 : offset+setLength]
		switch setID {
		case 0:
			if err := parseNetFlowV9Templates(session, body); err != nil {
				return nil, err
			}
		case 1:
			// ignore options templates in v0.1
		default:
			if setID >= 256 {
				template, ok := session.templates[setID]
				if ok {
					decoded, err := decodeDataRecords(template, body, datagram)
					if err != nil {
						return nil, err
					}
					records = append(records, decoded...)
				}
			}
		}

		offset += setLength
	}

	return records, nil
}

func (a *TemplateAdapter) decodeIPFIX(datagram Datagram) ([]Record, error) {
	payload := datagram.Payload
	if len(payload) < 16 {
		return nil, fmt.Errorf("ipfix datagram is truncated")
	}

	messageLength := int(binary.BigEndian.Uint16(payload[2:4]))
	if messageLength < 16 || messageLength > len(payload) {
		return nil, fmt.Errorf("ipfix message length is invalid")
	}
	payload = payload[:messageLength]

	session := a.ensureSession(sessionKey{
		Version:  10,
		Exporter: normalizeAddress(datagram.ExporterAddress),
		Domain:   binary.BigEndian.Uint32(payload[12:16]),
	})

	var records []Record
	for offset := 16; offset+4 <= len(payload); {
		setID := binary.BigEndian.Uint16(payload[offset : offset+2])
		setLength := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		if setLength < 4 || offset+setLength > len(payload) {
			return nil, fmt.Errorf("ipfix set length is invalid")
		}

		body := payload[offset+4 : offset+setLength]
		switch setID {
		case 2:
			if err := parseIPFIXTemplates(session, body); err != nil {
				return nil, err
			}
		case 3:
			// ignore options templates in v0.1
		default:
			if setID >= 256 {
				template, ok := session.templates[setID]
				if ok {
					decoded, err := decodeDataRecords(template, body, datagram)
					if err != nil {
						return nil, err
					}
					records = append(records, decoded...)
				}
			}
		}

		offset += setLength
	}

	return records, nil
}

func (a *TemplateAdapter) ensureSession(key sessionKey) *templateSession {
	if a.sessions == nil {
		a.sessions = make(map[sessionKey]*templateSession)
	}

	session, ok := a.sessions[key]
	if !ok {
		session = &templateSession{templates: make(map[uint16]flowTemplate)}
		a.sessions[key] = session
	}

	return session
}

func parseNetFlowV9Templates(session *templateSession, payload []byte) error {
	for offset := 0; offset+4 <= len(payload); {
		templateID := binary.BigEndian.Uint16(payload[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		template := flowTemplate{ID: templateID}
		for i := 0; i < fieldCount; i++ {
			if offset+4 > len(payload) {
				return fmt.Errorf("netflow v9 template is truncated")
			}
			field := templateField{
				Type:   binary.BigEndian.Uint16(payload[offset : offset+2]),
				Length: binary.BigEndian.Uint16(payload[offset+2 : offset+4]),
			}
			template.Fields = append(template.Fields, field)
			if field.Length == 0xffff {
				template.VariableField = true
			} else {
				template.RecordLength += int(field.Length)
			}
			offset += 4
		}

		session.templates[templateID] = template
	}

	return nil
}

func parseIPFIXTemplates(session *templateSession, payload []byte) error {
	for offset := 0; offset+4 <= len(payload); {
		templateID := binary.BigEndian.Uint16(payload[offset : offset+2])
		fieldCount := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		template := flowTemplate{ID: templateID}
		for i := 0; i < fieldCount; i++ {
			if offset+4 > len(payload) {
				return fmt.Errorf("ipfix template is truncated")
			}

			rawType := binary.BigEndian.Uint16(payload[offset : offset+2])
			field := templateField{
				Type:   rawType & 0x7fff,
				Length: binary.BigEndian.Uint16(payload[offset+2 : offset+4]),
			}
			offset += 4

			if rawType&0x8000 != 0 {
				if offset+4 > len(payload) {
					return fmt.Errorf("ipfix enterprise field is truncated")
				}
				offset += 4
			}

			template.Fields = append(template.Fields, field)
			if field.Length == 0xffff {
				template.VariableField = true
			} else {
				template.RecordLength += int(field.Length)
			}
		}

		session.templates[templateID] = template
	}

	return nil
}

func decodeDataRecords(template flowTemplate, payload []byte, datagram Datagram) ([]Record, error) {
	if template.VariableField || template.RecordLength <= 0 {
		return nil, nil
	}

	var records []Record
	for offset := 0; offset+template.RecordLength <= len(payload); offset += template.RecordLength {
		record, ok, err := decodeDataRecord(template, payload[offset:offset+template.RecordLength], datagram)
		if err != nil {
			return nil, err
		}
		if ok {
			records = append(records, record)
		}
	}

	return records, nil
}

func decodeDataRecord(template flowTemplate, payload []byte, datagram Datagram) (Record, bool, error) {
	record := Record{
		ExporterAddress: normalizeAddress(datagram.ExporterAddress),
		ObservedAt:      datagram.ReceivedAt.UTC(),
	}

	for offset, i := 0, 0; i < len(template.Fields); i++ {
		field := template.Fields[i]
		fieldLength := int(field.Length)
		if offset+fieldLength > len(payload) {
			return Record{}, false, fmt.Errorf("flow data record is truncated")
		}

		value := payload[offset : offset+fieldLength]
		switch field.Type {
		case 1:
			record.ByteCount = decodeUnsigned(value)
		case 2:
			record.PacketCount = decodeUnsigned(value)
		case 4:
			record.Protocol = protocolName(decodeUnsigned(value))
		case 7:
			record.SourcePort = uint16(decodeUnsigned(value))
		case 8, 27:
			record.SourceIP = decodeIP(value)
		case 11:
			record.DestinationPort = uint16(decodeUnsigned(value))
		case 12, 28:
			record.DestinationIP = decodeIP(value)
		}

		offset += fieldLength
	}

	record.SourceIP = normalizeAddress(record.SourceIP)
	record.DestinationIP = normalizeAddress(record.DestinationIP)
	if record.SourceIP == "" && record.DestinationIP == "" {
		return Record{}, false, nil
	}

	return record, true, nil
}

func (a *Aggregator) Add(records []Record) {
	if a == nil {
		return
	}

	for _, record := range records {
		a.addEndpoint(record, record.SourceIP, record.DestinationIP)
		a.addEndpoint(record, record.DestinationIP, record.SourceIP)
	}
}

func (a *Aggregator) addEndpoint(record Record, endpointIP string, peerIP string) {
	endpointIP = normalizeAddress(endpointIP)
	if endpointIP == "" {
		return
	}

	key := normalizeAddress(record.ExporterAddress) + "|" + endpointIP
	entry, ok := a.entries[key]
	if !ok {
		entry = &aggregateEntry{
			exporterAddress: normalizeAddress(record.ExporterAddress),
			endpointIP:      endpointIP,
			protocols:       make(map[string]uint64),
			ports:           make(map[uint16]uint64),
			peers:           make(map[string]uint64),
		}
		a.entries[key] = entry
	}

	if entry.firstSeen.IsZero() || (!record.ObservedAt.IsZero() && record.ObservedAt.Before(entry.firstSeen)) {
		entry.firstSeen = record.ObservedAt.UTC()
	}
	if record.ObservedAt.After(entry.lastSeen) {
		entry.lastSeen = record.ObservedAt.UTC()
	}

	entry.byteCount += record.ByteCount
	entry.packetCount += record.PacketCount
	entry.flowCount++

	if protocol := strings.TrimSpace(record.Protocol); protocol != "" {
		entry.protocols[protocol]++
	}
	if record.DestinationPort > 0 {
		entry.ports[record.DestinationPort]++
	}
	if peerIP = normalizeAddress(peerIP); peerIP != "" && peerIP != endpointIP {
		entry.peers[peerIP]++
	}
}

func (a *Aggregator) Observations(emitter EmitterConfig) []observations.Observation {
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
		if entry == nil || entry.endpointIP == "" || entry.lastSeen.IsZero() {
			continue
		}

		facts := make(map[string]any)
		if entry.exporterAddress != "" {
			facts["exporter_address"] = entry.exporterAddress
		}
		if protocols := sortedStringKeys(entry.protocols); len(protocols) > 0 {
			facts["protocols"] = protocols
		}
		if ports := topPorts(entry.ports, 5); len(ports) > 0 {
			facts["top_destination_ports"] = ports
		}
		if peers := topPeers(entry.peers, 10); len(peers) > 0 {
			facts["peer_ips"] = peers
		}

		results = append(results, observations.Observation{
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
				Capability: "flow",
			},
			ObservedAt: entry.lastSeen.UTC(),
			Addresses: &observations.Addresses{
				IPAddresses: []string{entry.endpointIP},
			},
			Facts: facts,
			Evidence: &observations.Evidence{
				Confidence:     0.45,
				SourceProtocol: "flow",
				FirstSeen:      timePointer(entry.firstSeen),
				LastSeen:       timePointer(entry.lastSeen),
				PacketCount:    toInt64(entry.packetCount),
				ByteCount:      toInt64(entry.byteCount),
				FlowCount:      toInt64(entry.flowCount),
			},
		})
	}

	return results
}

func decodeUnsigned(value []byte) uint64 {
	switch len(value) {
	case 1:
		return uint64(value[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(value))
	case 4:
		return uint64(binary.BigEndian.Uint32(value))
	case 8:
		return binary.BigEndian.Uint64(value)
	default:
		var result uint64
		for _, part := range value {
			result = (result << 8) | uint64(part)
		}
		return result
	}
}

func decodeIP(value []byte) string {
	if len(value) != net.IPv4len && len(value) != net.IPv6len {
		return ""
	}

	return normalizeAddress(net.IP(value).String())
}

func protocolName(value uint64) string {
	switch value {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	case 0:
		return ""
	default:
		return fmt.Sprintf("proto-%d", value)
	}
}

func normalizeAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return value
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

func sortedStringKeys(values map[string]uint64) []string {
	if len(values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func topPorts(values map[uint16]uint64, limit int) []int {
	if len(values) == 0 {
		return nil
	}

	type portCount struct {
		port  uint16
		count uint64
	}

	items := make([]portCount, 0, len(values))
	for port, count := range values {
		items = append(items, portCount{port: port, count: count})
	}
	sort.Slice(items, func(i int, j int) bool {
		if items[i].count == items[j].count {
			return items[i].port < items[j].port
		}
		return items[i].count > items[j].count
	})

	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}

	ports := make([]int, 0, len(items))
	for _, item := range items {
		ports = append(ports, int(item.port))
	}
	return ports
}

func topPeers(values map[string]uint64, limit int) []string {
	if len(values) == 0 {
		return nil
	}

	type peerCount struct {
		peer  string
		count uint64
	}

	items := make([]peerCount, 0, len(values))
	for peer, count := range values {
		items = append(items, peerCount{peer: peer, count: count})
	}
	sort.Slice(items, func(i int, j int) bool {
		if items[i].count == items[j].count {
			return items[i].peer < items[j].peer
		}
		return items[i].count > items[j].count
	})

	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}

	peers := make([]string, 0, len(items))
	for _, item := range items {
		peers = append(peers, item.peer)
	}
	return peers
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copyValue := value.UTC()
	return &copyValue
}

func toInt64(value uint64) int64 {
	const maxInt64 = ^uint64(0) >> 1
	if value > maxInt64 {
		return int64(maxInt64)
	}
	return int64(value)
}
