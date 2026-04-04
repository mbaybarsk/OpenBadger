package icmp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRawProberProbeIntegration(t *testing.T) {
	t.Parallel()

	target := strings.TrimSpace(os.Getenv("PING_TEST_TARGET"))
	if target == "" {
		t.Skip("set PING_TEST_TARGET to run ICMP integration tests")
	}

	ip, err := netip.ParseAddr(target)
	if err != nil {
		t.Fatalf("ParseAddr returned error: %v", err)
	}

	result, err := NewRawProber().Probe(context.Background(), ip, 2*time.Second)
	if err != nil {
		var netErr *net.OpError
		if errors.As(err, &netErr) && strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("ICMP integration test requires CAP_NET_RAW or root privileges")
		}

		t.Fatalf("Probe returned error: %v", err)
	}

	if result.IP != ip {
		t.Fatalf("result.IP = %q, want %q", result.IP, ip)
	}

	if result.ObservedAt.IsZero() {
		t.Fatal("result.ObservedAt is zero, want non-zero")
	}
}
