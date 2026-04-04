package pcap

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWindowProcessorLiveIntegration(t *testing.T) {
	t.Parallel()

	if strings.TrimSpace(os.Getenv("OPENBADGER_PCAP_LIVE_TEST")) == "" {
		t.Skip("set OPENBADGER_PCAP_LIVE_TEST=1 to run live pcap integration tests")
	}

	device := strings.TrimSpace(os.Getenv("OPENBADGER_PCAP_LIVE_TEST_INTERFACE"))
	if device == "" {
		device = "enp4s0"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	processor := NewWindowProcessor()
	_, err := processor.CaptureWindow(ctx, SourceConfig{Interface: device, SnapLen: 1600, ReadTimeout: 250 * time.Millisecond}, EmitterConfig{SiteID: "site-1", NodeID: "sensor-1", Name: "sensor-a", Version: "test"}, time.Second)
	if err == nil {
		return
	}

	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "operation not permitted"), strings.Contains(lower, "permission denied"):
		t.Skip("live pcap capture requires CAP_NET_RAW/CAP_NET_ADMIN or root privileges")
	case strings.Contains(lower, "no such device"), strings.Contains(lower, "doesn't exist"):
		t.Skip("interface enp4s0 is not available on this host")
	default:
		t.Fatalf("CaptureWindow returned error: %v", err)
	}
}
