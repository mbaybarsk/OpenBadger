package flow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/observations"
)

const (
	defaultWindow          = 10 * time.Second
	defaultReadTimeout     = 500 * time.Millisecond
	defaultMaxDatagramSize = 65535
)

type ReceiveConfig struct {
	ListenAddress   string
	Window          time.Duration
	ReadTimeout     time.Duration
	MaxDatagramSize int
}

type BatchHandler func(ctx context.Context, batch []observations.Observation) error

type Receiver struct {
	listenPacket func(network string, address string) (net.PacketConn, error)
	now          func() time.Time
	decoder      Decoder
}

func NewReceiver(decoder Decoder) *Receiver {
	if decoder == nil {
		decoder = NewTemplateAdapter()
	}

	return &Receiver{
		listenPacket: net.ListenPacket,
		now:          time.Now,
		decoder:      decoder,
	}
}

func (r *Receiver) Run(ctx context.Context, cfg ReceiveConfig, emitter EmitterConfig, handle BatchHandler) error {
	if r == nil {
		r = NewReceiver(nil)
	}
	if handle == nil {
		handle = func(context.Context, []observations.Observation) error { return nil }
	}

	listenAddress := strings.TrimSpace(cfg.ListenAddress)
	if listenAddress == "" {
		return fmt.Errorf("flow listen address is required")
	}

	window := cfg.Window
	if window <= 0 {
		window = defaultWindow
	}

	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}

	maxDatagramSize := cfg.MaxDatagramSize
	if maxDatagramSize <= 0 {
		maxDatagramSize = defaultMaxDatagramSize
	}

	conn, err := r.listenPacket("udp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer conn.Close()

	aggregator := NewAggregator()
	nextFlush := r.now().Add(window)
	buffer := make([]byte, maxDatagramSize)

	flush := func() error {
		batch := aggregator.Observations(emitter)
		aggregator = NewAggregator()
		nextFlush = r.now().Add(window)
		if len(batch) == 0 {
			return nil
		}
		return handle(ctx, batch)
	}

	for {
		if ctx.Err() != nil {
			return nil
		}

		now := r.now()
		if !now.Before(nextFlush) {
			if err := flush(); err != nil {
				return err
			}
			continue
		}

		deadline := nextFlush
		if timeoutDeadline := now.Add(readTimeout); timeoutDeadline.Before(deadline) {
			deadline = timeoutDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("set udp read deadline: %w", err)
		}

		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("read udp datagram: %w", err)
		}

		records, err := r.decoder.Decode(Datagram{
			ExporterAddress: exporterAddress(addr),
			ReceivedAt:      r.now().UTC(),
			Payload:         append([]byte(nil), buffer[:n]...),
		})
		if err == nil {
			aggregator.Add(records)
		}
	}
}

func exporterAddress(addr net.Addr) string {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return normalizeAddress(udpAddr.IP.String())
	}
	if addr == nil {
		return ""
	}
	return normalizeAddress(addr.String())
}
