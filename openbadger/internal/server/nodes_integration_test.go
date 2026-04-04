package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/nodes"
)

func TestEnrollHeartbeatFlowWithHTTPTestServer(t *testing.T) {
	t.Parallel()

	store := newMemoryNodeStore()
	fixedNow := time.Date(2026, time.April, 4, 9, 10, 0, 0, time.UTC)
	server := httptest.NewServer(newHandler(HandlerOptions{
		NodeService: newNodeService(store, "bootstrap-token", func() time.Time { return fixedNow }, func() (string, error) {
			return "issued-node-token", nil
		}),
	}))
	defer server.Close()

	client := nodes.NewClient(server.URL, server.Client())
	ctx := context.Background()

	enrollment, err := client.Enroll(ctx, "bootstrap-token", nodes.EnrollRequest{
		SiteID:       "site-1",
		Kind:         nodes.KindCollector,
		Name:         "collector-1",
		Version:      "0.1.0",
		Capabilities: []string{"ssh", "snmp"},
	})
	if err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}

	if enrollment.NodeID == "" {
		t.Fatal("enrollment.NodeID is empty")
	}

	heartbeat, err := client.Heartbeat(ctx, enrollment.AuthToken, nodes.HeartbeatRequest{
		Name:         "collector-1-renamed",
		Version:      "0.1.1",
		Capabilities: []string{"icmp", "ssh"},
		HealthStatus: "healthy",
	})
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}

	if heartbeat.Name != "collector-1-renamed" {
		t.Fatalf("heartbeat.Name = %q, want %q", heartbeat.Name, "collector-1-renamed")
	}

	if !heartbeat.LastHeartbeatAt.Equal(fixedNow) {
		t.Fatalf("heartbeat.LastHeartbeatAt = %s, want %s", heartbeat.LastHeartbeatAt, fixedNow)
	}

	response, err := server.Client().Get(server.URL + "/debug/nodes")
	if err != nil {
		t.Fatalf("GET /debug/nodes returned error: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	var payload struct {
		Nodes []nodes.DebugRecord `json:"nodes"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("json.Decode returned error: %v", err)
	}

	if len(payload.Nodes) != 1 {
		t.Fatalf("len(payload.Nodes) = %d, want %d", len(payload.Nodes), 1)
	}

	if payload.Nodes[0].Name != "collector-1-renamed" {
		t.Fatalf("payload.Nodes[0].Name = %q, want %q", payload.Nodes[0].Name, "collector-1-renamed")
	}
}
