package pcap

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParsePacketExtractsARPMetadata(t *testing.T) {
	t.Parallel()

	srcMAC := mustMAC(t, "00:11:22:33:44:55")
	packet := newPacket(t,
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: mustMAC(t, "ff:ff:ff:ff:ff:ff"), EthernetType: layers.EthernetTypeDot1Q},
		&layers.Dot1Q{VLANIdentifier: 50, Type: layers.EthernetTypeARP},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(srcMAC),
			SourceProtAddress: []byte(net.ParseIP("10.0.0.10").To4()),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(net.ParseIP("10.0.0.1").To4()),
		},
	)

	metadata := ParsePacket(packet, gopacket.CaptureInfo{Timestamp: time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC), Length: len(packet.Data())})
	if got, want := metadata.Protocols, []string{"arp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata.Protocols = %v, want %v", got, want)
	}

	if len(metadata.Endpoints) != 1 {
		t.Fatalf("len(metadata.Endpoints) = %d, want %d", len(metadata.Endpoints), 1)
	}

	endpoint := metadata.Endpoints[0]
	if endpoint.MAC != "00:11:22:33:44:55" {
		t.Fatalf("endpoint.MAC = %q, want %q", endpoint.MAC, "00:11:22:33:44:55")
	}

	if got, want := endpoint.IPs, []string{"10.0.0.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoint.IPs = %v, want %v", got, want)
	}

	if got, want := endpoint.VLANs, []int{50}; !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoint.VLANs = %v, want %v", got, want)
	}
}

func TestParsePacketExtractsDHCPHostname(t *testing.T) {
	t.Parallel()

	srcMAC := mustMAC(t, "00:11:22:33:44:55")
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4zero, DstIP: net.IPv4bcast}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returned error: %v", err)
	}

	packet := newPacket(t,
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: mustMAC(t, "ff:ff:ff:ff:ff:ff"), EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		udp,
		&layers.DHCPv4{
			Operation:    layers.DHCPOpRequest,
			HardwareType: layers.LinkTypeEthernet,
			HardwareLen:  6,
			Xid:          0x10203040,
			ClientHWAddr: srcMAC,
			Options: layers.DHCPOptions{
				{Type: layers.DHCPOptMessageType, Length: 1, Data: []byte{byte(layers.DHCPMsgTypeRequest)}},
				{Type: layers.DHCPOptHostname, Length: uint8(len("printer-lobby")), Data: []byte("printer-lobby")},
				{Type: layers.DHCPOptEnd},
			},
		},
	)

	metadata := ParsePacket(packet, gopacket.CaptureInfo{Timestamp: time.Date(2026, time.April, 4, 12, 1, 0, 0, time.UTC), Length: len(packet.Data())})
	endpoint := findEndpointByMAC(t, metadata.Endpoints, "00:11:22:33:44:55")
	if endpoint.DHCPHostname != "printer-lobby" {
		t.Fatalf("endpoint.DHCPHostname = %q, want %q", endpoint.DHCPHostname, "printer-lobby")
	}

	if got, want := metadata.Protocols, []string{"dhcp", "ipv4"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata.Protocols = %v, want %v", got, want)
	}
}

func TestParsePacketExtractsMDNSNames(t *testing.T) {
	t.Parallel()

	srcMAC := mustMAC(t, "00:11:22:33:44:55")
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("10.0.0.10").To4(), DstIP: net.ParseIP("224.0.0.251").To4()}
	udp := &layers.UDP{SrcPort: 5353, DstPort: 5353}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returned error: %v", err)
	}

	packet := newPacket(t,
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: mustMAC(t, "01:00:5e:00:00:fb"), EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		udp,
		&layers.DNS{
			QR: true,
			AA: true,
			Questions: []layers.DNSQuestion{{
				Name:  []byte("printer-lobby.local"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			}},
			Answers: []layers.DNSResourceRecord{{
				Name:  []byte("printer-lobby.local"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   120,
				IP:    net.ParseIP("10.0.0.10").To4(),
			}},
		},
	)

	metadata := ParsePacket(packet, gopacket.CaptureInfo{Timestamp: time.Date(2026, time.April, 4, 12, 2, 0, 0, time.UTC), Length: len(packet.Data())})
	endpoint := findEndpointByMAC(t, metadata.Endpoints, "00:11:22:33:44:55")
	if got, want := endpoint.MDNSNames, []string{"printer-lobby.local"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoint.MDNSNames = %v, want %v", got, want)
	}

	if got, want := metadata.Protocols, []string{"ipv4", "mdns"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata.Protocols = %v, want %v", got, want)
	}
}

func TestParsePacketExtractsNBNSName(t *testing.T) {
	t.Parallel()

	srcMAC := mustMAC(t, "00:11:22:33:44:55")
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("10.0.0.10").To4(), DstIP: net.ParseIP("10.0.0.255").To4()}
	udp := &layers.UDP{SrcPort: 137, DstPort: 137}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum returned error: %v", err)
	}

	packet := newPacket(t,
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: mustMAC(t, "ff:ff:ff:ff:ff:ff"), EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		udp,
		gopacket.Payload(newNBNSQueryPayload("WORKSTATION")),
	)

	metadata := ParsePacket(packet, gopacket.CaptureInfo{Timestamp: time.Date(2026, time.April, 4, 12, 3, 0, 0, time.UTC), Length: len(packet.Data())})
	endpoint := findEndpointByMAC(t, metadata.Endpoints, "00:11:22:33:44:55")
	if endpoint.NBNSName != "workstation" {
		t.Fatalf("endpoint.NBNSName = %q, want %q", endpoint.NBNSName, "workstation")
	}

	if got, want := metadata.Protocols, []string{"ipv4", "nbns"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata.Protocols = %v, want %v", got, want)
	}
}

func TestObservationAggregatorSummarizesMultiplePackets(t *testing.T) {
	t.Parallel()

	aggregator := NewObservationAggregator()
	firstSeen := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(2 * time.Second)

	aggregator.Add(PacketMetadata{
		Timestamp: firstSeen,
		Length:    60,
		Protocols: []string{"arp", "ipv4"},
		Endpoints: []EndpointMetadata{{MAC: "00:11:22:33:44:55", IPs: []string{"10.0.0.10"}, VLANs: []int{50}}},
	})
	aggregator.Add(PacketMetadata{
		Timestamp: lastSeen,
		Length:    80,
		Protocols: []string{"dhcp", "mdns"},
		Endpoints: []EndpointMetadata{{
			MAC:          "00:11:22:33:44:55",
			IPs:          []string{"10.0.0.10"},
			DHCPHostname: "printer-lobby",
			MDNSNames:    []string{"printer-lobby.local"},
		}},
	})

	observations := aggregator.Observations(EmitterConfig{SiteID: "site-1", NodeID: "sensor-1", Name: "sensor-a", Version: "test"})
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want %d", len(observations), 1)
	}

	observation := observations[0]
	if observation.Type != ObservationType {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, ObservationType)
	}

	if observation.Evidence == nil {
		t.Fatal("observation.Evidence = nil, want non-nil")
	}

	if observation.Evidence.PacketCount != 2 {
		t.Fatalf("observation.Evidence.PacketCount = %d, want %d", observation.Evidence.PacketCount, 2)
	}

	if observation.Evidence.ByteCount != 140 {
		t.Fatalf("observation.Evidence.ByteCount = %d, want %d", observation.Evidence.ByteCount, 140)
	}

	if observation.Evidence.FirstSeen == nil || !observation.Evidence.FirstSeen.Equal(firstSeen) {
		t.Fatalf("observation.Evidence.FirstSeen = %v, want %v", observation.Evidence.FirstSeen, firstSeen)
	}

	if observation.Evidence.LastSeen == nil || !observation.Evidence.LastSeen.Equal(lastSeen) {
		t.Fatalf("observation.Evidence.LastSeen = %v, want %v", observation.Evidence.LastSeen, lastSeen)
	}

	if got, want := observation.Facts["protocols"], []string{"arp", "dhcp", "ipv4", "mdns"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Facts[protocols] = %v, want %v", got, want)
	}

	if got, want := observation.Facts["dhcp_hostname"], "printer-lobby"; got != want {
		t.Fatalf("observation.Facts[dhcp_hostname] = %v, want %v", got, want)
	}

	if got, want := observation.Facts["mdns_names"], []string{"printer-lobby.local"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Facts[mdns_names] = %v, want %v", got, want)
	}

	if observation.Addresses == nil {
		t.Fatal("observation.Addresses = nil, want non-nil")
	}

	if got, want := observation.Addresses.VLANIDs, []int{50}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Addresses.VLANIDs = %v, want %v", got, want)
	}
}

func TestWindowProcessorCaptureWindowReadsOfflineFixture(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("..", "..", "..", "test", "fixtures", "passive", "passive_metadata_sample.pcap")

	processor := NewWindowProcessor()
	observations, err := processor.CaptureWindow(context.Background(), SourceConfig{FilePath: fixturePath}, EmitterConfig{SiteID: "site-1", NodeID: "sensor-1", Name: "sensor-a", Version: "test"}, time.Second)
	if err != nil {
		t.Fatalf("CaptureWindow returned error: %v", err)
	}

	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want %d", len(observations), 1)
	}

	observation := observations[0]
	if got, want := observation.Identifiers.MACAddresses, []string{"00:11:22:33:44:55"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Identifiers.MACAddresses = %v, want %v", got, want)
	}

	if got, want := observation.Addresses.IPAddresses, []string{"10.0.0.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Addresses.IPAddresses = %v, want %v", got, want)
	}

	if got, want := observation.Addresses.VLANIDs, []int{50}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Addresses.VLANIDs = %v, want %v", got, want)
	}

	if got, want := observation.Facts["protocols"], []string{"arp", "dhcp", "ipv4", "mdns", "nbns"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Facts[protocols] = %v, want %v", got, want)
	}

	if got, want := observation.Facts["dhcp_hostname"], "printer-lobby"; got != want {
		t.Fatalf("observation.Facts[dhcp_hostname] = %v, want %v", got, want)
	}

	if got, want := observation.Facts["mdns_names"], []string{"printer-lobby.local"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Facts[mdns_names] = %v, want %v", got, want)
	}

	if got, want := observation.Facts["nbns_name"], "workstation"; got != want {
		t.Fatalf("observation.Facts[nbns_name] = %v, want %v", got, want)
	}

	if observation.Evidence == nil || observation.Evidence.PacketCount != 4 {
		t.Fatalf("observation.Evidence.PacketCount = %v, want %d", observation.Evidence, 4)
	}
}

func newPacket(t *testing.T, serializableLayers ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, serializableLayers...); err != nil {
		t.Fatalf("SerializeLayers returned error: %v", err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()

	addr, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("ParseMAC returned error: %v", err)
	}

	return addr
}

func findEndpointByMAC(t *testing.T, endpoints []EndpointMetadata, wantMAC string) EndpointMetadata {
	t.Helper()

	for _, endpoint := range endpoints {
		if endpoint.MAC == wantMAC {
			return endpoint
		}
	}

	t.Fatalf("did not find endpoint with MAC %q", wantMAC)
	return EndpointMetadata{}
}

func newNBNSQueryPayload(name string) []byte {
	encoded := encodeNBNSName(name)
	payload := []byte{0x12, 0x34, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}
	payload = append(payload, encoded...)
	payload = append(payload, 0x00, 0x00, 0x20, 0x00, 0x01)
	return payload
}

func encodeNBNSName(name string) []byte {
	bytes := make([]byte, 16)
	copy(bytes, []byte(name))
	for i := len(name); i < 15; i++ {
		bytes[i] = ' '
	}

	encoded := make([]byte, 0, 32)
	for _, value := range bytes {
		high := 'A' + ((value >> 4) & 0x0f)
		low := 'A' + (value & 0x0f)
		encoded = append(encoded, byte(high), byte(low))
	}

	return encoded
}
