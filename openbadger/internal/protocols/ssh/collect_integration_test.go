package ssh

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
)

func TestCollectIntegration(t *testing.T) {
	t.Parallel()

	host := strings.TrimSpace(os.Getenv("SSH_TEST_HOST"))
	user := strings.TrimSpace(os.Getenv("SSH_TEST_USER"))
	password := os.Getenv("SSH_TEST_PASSWORD")
	rawKey := os.Getenv("SSH_TEST_KEY")
	if host == "" || user == "" || (password == "" && strings.TrimSpace(rawKey) == "") {
		t.Skip("set SSH_TEST_HOST, SSH_TEST_USER, and SSH_TEST_PASSWORD or SSH_TEST_KEY to run SSH integration tests")
	}

	if trimmed := strings.TrimSpace(rawKey); trimmed != "" {
		if content, err := os.ReadFile(trimmed); err == nil {
			rawKey = string(content)
		}
	}

	port := 22
	if rawPort := strings.TrimSpace(os.Getenv("SSH_TEST_PORT")); rawPort != "" {
		parsed, err := strconv.Atoi(rawPort)
		if err != nil {
			t.Fatalf("Atoi returned error: %v", err)
		}
		port = parsed
	}

	credential := credentials.SSHProfile{Username: user, Port: port}
	if password != "" {
		credential.Password = password
	} else {
		credential.PrivateKey = rawKey
	}

	result, err := NewCollector().Collect(context.Background(), Request{
		Target:     host,
		Port:       port,
		Timeout:    5 * time.Second,
		Credential: credential,
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if strings.TrimSpace(result.HostKeyFingerprint) == "" {
		t.Fatal("result.HostKeyFingerprint is empty, want non-empty fingerprint")
	}

	if strings.TrimSpace(result.Hostname) == "" && strings.TrimSpace(result.FQDN) == "" {
		t.Fatalf("result = %#v, want hostname or fqdn", result)
	}

	if strings.TrimSpace(result.KernelVersion) == "" || strings.TrimSpace(result.Architecture) == "" {
		t.Fatalf("result = %#v, want kernel version and architecture", result)
	}
}
