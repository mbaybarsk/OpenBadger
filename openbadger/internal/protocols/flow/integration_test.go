package flow

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/observations"
)

func TestReceiverLiveUDPIntegration(t *testing.T) {
	t.Parallel()

	if strings.TrimSpace(os.Getenv("OPENBADGER_FLOW_LIVE_TEST")) == "" {
		t.Skip("set OPENBADGER_FLOW_LIVE_TEST=1 to run live UDP flow receiver tests")
	}

	listenAddress := strings.TrimSpace(os.Getenv("OPENBADGER_FLOW_LIVE_TEST_ADDR"))
	if listenAddress == "" {
		t.Skip("set OPENBADGER_FLOW_LIVE_TEST_ADDR to run live UDP flow receiver tests")
	}

	receiver := NewReceiver(NewTemplateAdapter())
	batchCh := make(chan []observations.Observation, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = receiver.Run(ctx, ReceiveConfig{
			ListenAddress:   listenAddress,
			Window:          200 * time.Millisecond,
			ReadTimeout:     50 * time.Millisecond,
			MaxDatagramSize: 2048,
		}, EmitterConfig{SiteID: "site-1", NodeID: "sensor-1", Name: "sensor-a", Version: "test"}, func(ctx context.Context, batch []observations.Observation) error {
			select {
			case batchCh <- batch:
			default:
			}
			return nil
		})
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("udp", listenAddress)
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
		if len(batch) == 0 {
			t.Fatal("received empty batch, want observations")
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for live UDP receiver batch: %v", ctx.Err())
	}
}
