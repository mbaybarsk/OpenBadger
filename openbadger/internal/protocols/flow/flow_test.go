package flow

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/observations"
)

func TestTemplateAdapterDecodeNetFlowV9Fixtures(t *testing.T) {
	t.Parallel()

	adapter := NewTemplateAdapter()
	receivedAt := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)

	templatePacket := readFixtureHex(t, "netflow_v9_template.hex")
	dataPacket := readFixtureHex(t, "netflow_v9_data_1.hex")

	records, err := adapter.Decode(Datagram{ExporterAddress: "192.0.2.10", ReceivedAt: receivedAt, Payload: templatePacket})
	if err != nil {
		t.Fatalf("Decode(template) returned error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(records) for template = %d, want %d", len(records), 0)
	}

	records, err = adapter.Decode(Datagram{ExporterAddress: "192.0.2.10", ReceivedAt: receivedAt, Payload: dataPacket})
	if err != nil {
		t.Fatalf("Decode(data) returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want %d", len(records), 1)
	}

	record := records[0]
	if record.SourceIP != "10.0.0.10" {
		t.Fatalf("record.SourceIP = %q, want %q", record.SourceIP, "10.0.0.10")
	}
	if record.DestinationIP != "10.0.0.1" {
		t.Fatalf("record.DestinationIP = %q, want %q", record.DestinationIP, "10.0.0.1")
	}
	if record.DestinationPort != 443 {
		t.Fatalf("record.DestinationPort = %d, want %d", record.DestinationPort, 443)
	}
	if record.Protocol != "tcp" {
		t.Fatalf("record.Protocol = %q, want %q", record.Protocol, "tcp")
	}
	if record.ByteCount != 1000 {
		t.Fatalf("record.ByteCount = %d, want %d", record.ByteCount, 1000)
	}
	if record.PacketCount != 10 {
		t.Fatalf("record.PacketCount = %d, want %d", record.PacketCount, 10)
	}
}

func TestTemplateAdapterDecodeIPFIXFixtures(t *testing.T) {
	t.Parallel()

	adapter := NewTemplateAdapter()
	receivedAt := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)

	templatePacket := readFixtureHex(t, "ipfix_template.hex")
	dataPacket := readFixtureHex(t, "ipfix_data_1.hex")

	if _, err := adapter.Decode(Datagram{ExporterAddress: "192.0.2.20", ReceivedAt: receivedAt, Payload: templatePacket}); err != nil {
		t.Fatalf("Decode(template) returned error: %v", err)
	}

	records, err := adapter.Decode(Datagram{ExporterAddress: "192.0.2.20", ReceivedAt: receivedAt, Payload: dataPacket})
	if err != nil {
		t.Fatalf("Decode(data) returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want %d", len(records), 1)
	}

	record := records[0]
	if record.SourceIP != "10.0.0.20" {
		t.Fatalf("record.SourceIP = %q, want %q", record.SourceIP, "10.0.0.20")
	}
	if record.DestinationIP != "10.0.0.3" {
		t.Fatalf("record.DestinationIP = %q, want %q", record.DestinationIP, "10.0.0.3")
	}
	if record.DestinationPort != 80 {
		t.Fatalf("record.DestinationPort = %d, want %d", record.DestinationPort, 80)
	}
	if record.Protocol != "tcp" {
		t.Fatalf("record.Protocol = %q, want %q", record.Protocol, "tcp")
	}
	if record.ByteCount != 2000 {
		t.Fatalf("record.ByteCount = %d, want %d", record.ByteCount, 2000)
	}
	if record.PacketCount != 20 {
		t.Fatalf("record.PacketCount = %d, want %d", record.PacketCount, 20)
	}
}

func TestAggregatorSummarizesFlowRecords(t *testing.T) {
	t.Parallel()

	aggregator := NewAggregator()
	firstSeen := time.Date(2026, time.April, 4, 12, 10, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(2 * time.Second)
	aggregator.Add([]Record{
		{
			ExporterAddress: "192.0.2.10",
			ObservedAt:      firstSeen,
			SourceIP:        "10.0.0.10",
			DestinationIP:   "10.0.0.1",
			DestinationPort: 443,
			Protocol:        "tcp",
			ByteCount:       1000,
			PacketCount:     10,
		},
		{
			ExporterAddress: "192.0.2.10",
			ObservedAt:      lastSeen,
			SourceIP:        "10.0.0.10",
			DestinationIP:   "10.0.0.2",
			DestinationPort: 53,
			Protocol:        "udp",
			ByteCount:       500,
			PacketCount:     5,
		},
	})

	observations := aggregator.Observations(EmitterConfig{SiteID: "site-1", NodeID: "sensor-1", Name: "sensor-a", Version: "test"})
	if len(observations) != 3 {
		t.Fatalf("len(observations) = %d, want %d", len(observations), 3)
	}

	observation := observationByIP(t, observations, "10.0.0.10")
	if observation.Type != ObservationType {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, ObservationType)
	}
	if observation.Evidence == nil {
		t.Fatal("observation.Evidence = nil, want non-nil")
	}
	if observation.Evidence.FlowCount != 2 {
		t.Fatalf("observation.Evidence.FlowCount = %d, want %d", observation.Evidence.FlowCount, 2)
	}
	if observation.Evidence.PacketCount != 15 {
		t.Fatalf("observation.Evidence.PacketCount = %d, want %d", observation.Evidence.PacketCount, 15)
	}
	if observation.Evidence.ByteCount != 1500 {
		t.Fatalf("observation.Evidence.ByteCount = %d, want %d", observation.Evidence.ByteCount, 1500)
	}
	if observation.Evidence.FirstSeen == nil || !observation.Evidence.FirstSeen.Equal(firstSeen) {
		t.Fatalf("observation.Evidence.FirstSeen = %v, want %v", observation.Evidence.FirstSeen, firstSeen)
	}
	if observation.Evidence.LastSeen == nil || !observation.Evidence.LastSeen.Equal(lastSeen) {
		t.Fatalf("observation.Evidence.LastSeen = %v, want %v", observation.Evidence.LastSeen, lastSeen)
	}
	if got, want := observation.Facts["protocols"], []string{"tcp", "udp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Facts[protocols] = %v, want %v", got, want)
	}
	if got, want := observation.Facts["top_destination_ports"], []int{53, 443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Facts[top_destination_ports] = %v, want %v", got, want)
	}
	if got, want := observation.Facts["peer_ips"], []string{"10.0.0.1", "10.0.0.2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("observation.Facts[peer_ips] = %v, want %v", got, want)
	}
	if got, want := observation.Facts["exporter_address"], "192.0.2.10"; got != want {
		t.Fatalf("observation.Facts[exporter_address] = %v, want %v", got, want)
	}
}

func TestReceiverRunReadsFixtureDatagrams(t *testing.T) {
	t.Parallel()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}

	receiver := NewReceiver(NewTemplateAdapter())
	receiver.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return listener, nil
	}

	batchCh := make(chan []observations.Observation, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go func() {
		_ = receiver.Run(ctx, ReceiveConfig{
			ListenAddress:   listener.LocalAddr().String(),
			Window:          100 * time.Millisecond,
			ReadTimeout:     20 * time.Millisecond,
			MaxDatagramSize: 2048,
		}, EmitterConfig{SiteID: "site-1", NodeID: "sensor-1", Name: "sensor-a", Version: "test"}, func(ctx context.Context, batch []observations.Observation) error {
			select {
			case batchCh <- batch:
			default:
			}
			cancel()
			return nil
		})
	}()

	conn, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer conn.Close()

	for _, name := range []string{"netflow_v9_template.hex", "netflow_v9_data_1.hex", "netflow_v9_data_2.hex"} {
		if _, err := conn.Write(readFixtureHex(t, name)); err != nil {
			t.Fatalf("Write(%s) returned error: %v", name, err)
		}
	}

	select {
	case batch := <-batchCh:
		observation := observationByIP(t, batch, "10.0.0.10")
		if observation.Evidence == nil || observation.Evidence.FlowCount != 2 {
			t.Fatalf("observation.Evidence.FlowCount = %v, want %d", observation.Evidence, 2)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for receiver batch")
	}
}

func observationByIP(t *testing.T, batch []observations.Observation, ipAddress string) observations.Observation {
	t.Helper()

	for _, observation := range batch {
		if observation.Addresses == nil {
			continue
		}
		for _, candidate := range observation.Addresses.IPAddresses {
			if candidate == ipAddress {
				return observation
			}
		}
	}

	t.Fatalf("did not find observation for IP %q", ipAddress)
	return observations.Observation{}
}

func readFixtureHex(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("..", "..", "..", "test", "fixtures", "flow", name)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) returned error: %v", path, err)
	}

	decoded, err := hex.DecodeString(string(trimWhitespace(contents)))
	if err != nil {
		t.Fatalf("DecodeString(%s) returned error: %v", path, err)
	}

	return decoded
}

func trimWhitespace(value []byte) []byte {
	trimmed := make([]byte, 0, len(value))
	for _, b := range value {
		switch b {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			trimmed = append(trimmed, b)
		}
	}
	return trimmed
}
