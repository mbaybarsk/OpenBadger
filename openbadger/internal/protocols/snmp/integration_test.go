package snmp

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
)

func TestCollectorIntegration(t *testing.T) {
	t.Parallel()

	target := strings.TrimSpace(os.Getenv("SNMP_TEST_TARGET"))
	if target == "" {
		t.Skip("set SNMP_TEST_TARGET and SNMP_TEST_COMMUNITY or SNMP_TEST_V3_USERNAME to run SNMP integration tests")
	}

	profile, ok := snmpTestProfile()
	if !ok {
		t.Skip("set SNMP_TEST_COMMUNITY for v2c or SNMP_TEST_V3_USERNAME for v3 integration tests")
	}

	collector := NewCollector(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := collector.Collect(ctx, Request{
		Target:     target,
		Port:       profile.Port,
		Timeout:    5 * time.Second,
		Retries:    1,
		Credential: profile,
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if result.System.SysName == "" && result.System.SysDescr == "" && result.System.SysObjectID == "" {
		t.Fatalf("result.System = %#v, want at least one system fact", result.System)
	}
}

func snmpTestProfile() (credentials.SNMPProfile, bool) {
	if community := strings.TrimSpace(os.Getenv("SNMP_TEST_COMMUNITY")); community != "" {
		return credentials.SNMPProfile{
			Version:   credentials.SNMPVersion2c,
			Community: community,
		}, true
	}

	if username := strings.TrimSpace(os.Getenv("SNMP_TEST_V3_USERNAME")); username != "" {
		return credentials.SNMPProfile{
			Version:         credentials.SNMPVersion3,
			Username:        username,
			AuthProtocol:    strings.TrimSpace(os.Getenv("SNMP_TEST_V3_AUTH_PROTOCOL")),
			AuthPassword:    strings.TrimSpace(os.Getenv("SNMP_TEST_V3_AUTH_PASSWORD")),
			PrivacyProtocol: strings.TrimSpace(os.Getenv("SNMP_TEST_V3_PRIV_PROTOCOL")),
			PrivacyPassword: strings.TrimSpace(os.Getenv("SNMP_TEST_V3_PRIV_PASSWORD")),
		}, true
	}

	return credentials.SNMPProfile{}, false
}
