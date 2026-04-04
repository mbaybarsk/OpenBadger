package main

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	outPath := filepath.Join("test", "fixtures", "passive", "passive_metadata_sample.pcap")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		log.Fatal(err)
	}

	file, err := os.Create(outPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}

	srcMAC := mustMAC("00:11:22:33:44:55")
	broadcast := mustMAC("ff:ff:ff:ff:ff:ff")
	mdnsMulticast := mustMAC("01:00:5e:00:00:fb")

	packets := []struct {
		when time.Time
		data []byte
	}{
		{
			when: time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC),
			data: packet(
				&layers.Ethernet{SrcMAC: srcMAC, DstMAC: broadcast, EthernetType: layers.EthernetTypeDot1Q},
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
			),
		},
		{
			when: time.Date(2026, time.April, 4, 12, 0, 1, 0, time.UTC),
			data: dhcpPacket(srcMAC, broadcast),
		},
		{
			when: time.Date(2026, time.April, 4, 12, 0, 2, 0, time.UTC),
			data: mdnsPacket(srcMAC, mdnsMulticast),
		},
		{
			when: time.Date(2026, time.April, 4, 12, 0, 3, 0, time.UTC),
			data: nbnsPacket(srcMAC, broadcast),
		},
	}

	for _, pkt := range packets {
		ci := gopacket.CaptureInfo{Timestamp: pkt.when, CaptureLength: len(pkt.data), Length: len(pkt.data)}
		if err := writer.WritePacket(ci, pkt.data); err != nil {
			log.Fatal(err)
		}
	}
}

func dhcpPacket(srcMAC, dstMAC net.HardwareAddr) []byte {
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4zero, DstIP: net.IPv4bcast}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		log.Fatal(err)
	}

	return packet(
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4},
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
}

func mdnsPacket(srcMAC, dstMAC net.HardwareAddr) []byte {
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("10.0.0.10").To4(), DstIP: net.ParseIP("224.0.0.251").To4()}
	udp := &layers.UDP{SrcPort: 5353, DstPort: 5353}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		log.Fatal(err)
	}

	return packet(
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		udp,
		&layers.DNS{
			QR: true,
			AA: true,
			Answers: []layers.DNSResourceRecord{{
				Name:  []byte("printer-lobby.local"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   120,
				IP:    net.ParseIP("10.0.0.10").To4(),
			}},
		},
	)
}

func nbnsPacket(srcMAC, dstMAC net.HardwareAddr) []byte {
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("10.0.0.10").To4(), DstIP: net.ParseIP("10.0.0.255").To4()}
	udp := &layers.UDP{SrcPort: 137, DstPort: 137}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		log.Fatal(err)
	}

	return packet(
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4},
		ipv4,
		udp,
		gopacket.Payload(nbnsQueryPayload("WORKSTATION")),
	)
}

func packet(parts ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, parts...); err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

func mustMAC(raw string) net.HardwareAddr {
	addr, err := net.ParseMAC(raw)
	if err != nil {
		log.Fatal(err)
	}
	return addr
}

func nbnsQueryPayload(name string) []byte {
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
