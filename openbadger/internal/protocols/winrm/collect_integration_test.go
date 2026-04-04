package winrm

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
)

func TestCollectIntegration(t *testing.T) {
	t.Parallel()

	host := os.Getenv("WINRM_TEST_HOST")
	user := os.Getenv("WINRM_TEST_USER")
	password := os.Getenv("WINRM_TEST_PASSWORD")
	if host == "" || user == "" || password == "" {
		t.Skip("set WINRM_TEST_HOST, WINRM_TEST_USER, and WINRM_TEST_PASSWORD to run WinRM integration tests")
	}

	useHTTPS := true
	if raw := os.Getenv("WINRM_TEST_HTTPS"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("strconv.ParseBool returned error: %v", err)
		}
		useHTTPS = parsed
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := NewCollector().Collect(ctx, Request{
		Target:  host,
		Timeout: 15 * time.Second,
		Credential: credentials.WinRMProfile{
			Username:    user,
			Password:    password,
			UseHTTPS:    boolRef(useHTTPS),
			AllowHTTP:   !useHTTPS,
			InsecureTLS: useHTTPS,
		},
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if result.Hostname == "" {
		t.Fatal("result.Hostname = empty, want hostname")
	}

	if len(result.NetworkAddresses) == 0 {
		t.Fatal("result.NetworkAddresses = empty, want at least one address")
	}
}

func boolRef(value bool) *bool {
	return &value
}
