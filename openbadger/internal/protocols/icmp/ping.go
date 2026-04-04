package icmp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
	defaultTimeout  = time.Second
)

var ErrNoReply = errors.New("icmp no reply")

type Result struct {
	IP         netip.Addr
	RTT        time.Duration
	TTL        int
	ObservedAt time.Time
}

type Prober interface {
	Probe(ctx context.Context, ip netip.Addr, timeout time.Duration) (Result, error)
}

type RawProber struct{}

func NewRawProber() *RawProber {
	return &RawProber{}
}

func (p *RawProber) Probe(ctx context.Context, ip netip.Addr, timeout time.Duration) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	if !ip.IsValid() {
		return Result{}, fmt.Errorf("icmp probe target is required")
	}

	if !ip.Is4() {
		return Result{}, fmt.Errorf("icmp probe target %q must be an IPv4 address", ip.String())
	}

	if timeout <= 0 {
		timeout = defaultTimeout
	}

	startedAt := time.Now().UTC()
	deadline := startedAt.Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.IP(ip.AsSlice())})
	if err != nil {
		return Result{}, fmt.Errorf("open raw icmp socket: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return Result{}, fmt.Errorf("set icmp deadline: %w", err)
	}

	identifier := uint16(os.Getpid() & 0xffff)
	sequence := uint16(startedAt.UnixNano())
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(startedAt.UnixNano()))
	request := marshalEchoRequest(identifier, sequence, payload)

	if _, err := conn.Write(request); err != nil {
		return Result{}, fmt.Errorf("send icmp echo request: %w", err)
	}

	buffer := make([]byte, 1500)
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		n, err := conn.Read(buffer)
		if err != nil {
			if isDeadlineError(err) {
				return Result{}, ErrNoReply
			}

			return Result{}, fmt.Errorf("read icmp echo reply: %w", err)
		}

		reply, ttl, err := parseEchoReply(buffer[:n])
		if err != nil {
			continue
		}

		if reply.Type != icmpEchoReply || reply.Code != 0 {
			continue
		}

		if reply.Identifier != identifier || reply.Sequence != sequence {
			continue
		}

		observedAt := time.Now().UTC()
		return Result{
			IP:         ip,
			RTT:        observedAt.Sub(startedAt),
			TTL:        ttl,
			ObservedAt: observedAt,
		}, nil
	}
}

type NormalizeRequest struct {
	SiteID      string
	JobID       string
	NodeKind    string
	NodeID      string
	NodeName    string
	Version     string
	TargetInput string
	IP          netip.Addr
	ObservedAt  time.Time
	RTT         time.Duration
	TTL         int
}

func NormalizeAliveObservation(request NormalizeRequest) (observations.Observation, error) {
	if strings.TrimSpace(request.SiteID) == "" {
		return observations.Observation{}, fmt.Errorf("icmp observation site id is required")
	}

	if strings.TrimSpace(request.NodeID) == "" {
		return observations.Observation{}, fmt.Errorf("icmp observation node id is required")
	}

	if !request.IP.IsValid() {
		return observations.Observation{}, fmt.Errorf("icmp observation ip is required")
	}

	if request.ObservedAt.IsZero() {
		return observations.Observation{}, fmt.Errorf("icmp observation observed_at is required")
	}

	observedAt := request.ObservedAt.UTC().Truncate(time.Second)
	ip := request.IP.String()
	targetInput := strings.TrimSpace(request.TargetInput)
	if targetInput == "" {
		targetInput = ip
	}

	facts := make(map[string]any)
	if request.RTT > 0 {
		facts["rtt_ms"] = float64(request.RTT.Microseconds()) / 1000
	}
	if request.TTL > 0 {
		facts["ttl"] = request.TTL
	}

	return observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          "icmp.alive",
		Scope:         "sighting",
		SiteID:        strings.TrimSpace(request.SiteID),
		JobID:         strings.TrimSpace(request.JobID),
		Emitter: &observations.Emitter{
			Kind:       strings.TrimSpace(request.NodeKind),
			ID:         strings.TrimSpace(request.NodeID),
			Name:       strings.TrimSpace(request.NodeName),
			Version:    strings.TrimSpace(request.Version),
			Capability: "icmp",
		},
		ObservedAt: observedAt,
		Target: &observations.Target{
			Input:    targetInput,
			IP:       ip,
			Protocol: "icmp",
		},
		Addresses: &observations.Addresses{
			IPAddresses: []string{ip},
		},
		Facts: facts,
		Evidence: &observations.Evidence{
			Confidence:     0.6,
			SourceProtocol: "icmp",
			FirstSeen:      timeRef(observedAt),
			LastSeen:       timeRef(observedAt),
		},
	}, nil
}

type echoMessage struct {
	Type       uint8
	Code       uint8
	Identifier uint16
	Sequence   uint16
}

func marshalEchoRequest(identifier uint16, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 8+len(payload))
	packet[0] = icmpEchoRequest
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[4:6], identifier)
	binary.BigEndian.PutUint16(packet[6:8], sequence)
	copy(packet[8:], payload)
	binary.BigEndian.PutUint16(packet[2:4], checksum(packet))
	return packet
}

func parseEchoReply(packet []byte) (echoMessage, int, error) {
	ttl := 0
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength+8 {
			return echoMessage{}, 0, fmt.Errorf("icmp reply is truncated")
		}

		ttl = int(packet[8])
		packet = packet[headerLength:]
	}

	if len(packet) < 8 {
		return echoMessage{}, 0, fmt.Errorf("icmp reply is truncated")
	}

	return echoMessage{
		Type:       packet[0],
		Code:       packet[1],
		Identifier: binary.BigEndian.Uint16(packet[4:6]),
		Sequence:   binary.BigEndian.Uint16(packet[6:8]),
	}, ttl, nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

func isDeadlineError(err error) bool {
	var netErr net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func timeRef(value time.Time) *time.Time {
	copy := value
	return &copy
}
