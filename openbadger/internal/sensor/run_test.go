package sensor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mbaybarsk/openbadger/internal/config"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
	flowprotocol "github.com/mbaybarsk/openbadger/internal/protocols/flow"
)

func TestNewCaptureRunnerRequiresSource(t *testing.T) {
	t.Parallel()

	_, err := newCaptureRunner(config.SensorConfig{}, nil)
	if err == nil {
		t.Fatal("newCaptureRunner returned nil error, want error")
	}

	if err.Error() != "sensor capture interface or pcap file is required" {
		t.Fatalf("newCaptureRunner error = %q, want %q", err.Error(), "sensor capture interface or pcap file is required")
	}
}

func TestNewSensorRunnerAllowsFlowOnlySource(t *testing.T) {
	t.Parallel()

	runner, err := newSensorRunner(config.SensorConfig{FlowListenAddress: "127.0.0.1:2055"}, nil)
	if err != nil {
		t.Fatalf("newSensorRunner returned error: %v", err)
	}
	if runner.flow == nil {
		t.Fatal("runner.flow = nil, want non-nil")
	}
	if runner.capture != nil {
		t.Fatal("runner.capture != nil, want nil")
	}
}

func TestNewFlowRunnerRequiresListenAddress(t *testing.T) {
	t.Parallel()

	_, err := newFlowRunner(config.SensorConfig{}, nil)
	if err == nil {
		t.Fatal("newFlowRunner returned nil error, want error")
	}
	if err.Error() != "sensor flow listen address is required" {
		t.Fatalf("newFlowRunner error = %q, want %q", err.Error(), "sensor flow listen address is required")
	}
}

func TestCaptureRunnerLoopUploadsPassiveObservations(t *testing.T) {
	t.Parallel()

	var uploaded observations.BatchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/observations/batch" {
			t.Fatalf("request path = %q, want %q", r.URL.Path, "/api/v1/observations/batch")
		}

		if got := r.Header.Get("Authorization"); got != "Bearer auth-token" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer auth-token")
		}

		if err := json.NewDecoder(r.Body).Decode(&uploaded); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(observations.BatchResponse{Accepted: len(uploaded.Observations)})
	}))
	defer server.Close()

	runner, err := newCaptureRunner(config.SensorConfig{
		PCAPFile:      filepath.Join("..", "..", "test", "fixtures", "passive", "passive_metadata_sample.pcap"),
		CaptureWindow: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newCaptureRunner returned error: %v", err)
	}

	runner.loop(context.Background(), nodes.NewClient(server.URL, nil), nodes.State{
		NodeID:    "sensor-1",
		SiteID:    "site-1",
		Kind:      nodes.KindSensor,
		Name:      "sensor-a",
		AuthToken: "auth-token",
	})

	if len(uploaded.Observations) != 1 {
		t.Fatalf("len(uploaded.Observations) = %d, want %d", len(uploaded.Observations), 1)
	}

	observation := uploaded.Observations[0]
	if observation.Type != "passive.pcap_sighting" {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, "passive.pcap_sighting")
	}

	if observation.SiteID != "site-1" {
		t.Fatalf("observation.SiteID = %q, want %q", observation.SiteID, "site-1")
	}
}

func TestFlowRunnerLoopUploadsFlowObservations(t *testing.T) {
	t.Parallel()

	var uploaded observations.BatchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/observations/batch" {
			t.Fatalf("request path = %q, want %q", r.URL.Path, "/api/v1/observations/batch")
		}

		if got := r.Header.Get("Authorization"); got != "Bearer auth-token" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer auth-token")
		}

		if err := json.NewDecoder(r.Body).Decode(&uploaded); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(observations.BatchResponse{Accepted: len(uploaded.Observations)})
	}))
	defer server.Close()

	fakeReceiver := &fakeFlowReceiver{}
	runner := &flowRunner{
		cfg: config.SensorConfig{
			CaptureWindow:     time.Second,
			FlowListenAddress: "127.0.0.1:2055",
			FlowReadTimeout:   200 * time.Millisecond,
			FlowMaxDatagram:   4096,
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		receiver: fakeReceiver,
	}

	runner.loop(context.Background(), nodes.NewClient(server.URL, nil), nodes.State{
		NodeID:    "sensor-1",
		SiteID:    "site-1",
		Kind:      nodes.KindSensor,
		Name:      "sensor-a",
		AuthToken: "auth-token",
	})

	if len(uploaded.Observations) != 1 {
		t.Fatalf("len(uploaded.Observations) = %d, want %d", len(uploaded.Observations), 1)
	}

	observation := uploaded.Observations[0]
	if observation.Type != flowprotocol.ObservationType {
		t.Fatalf("observation.Type = %q, want %q", observation.Type, flowprotocol.ObservationType)
	}
	if fakeReceiver.cfg.ListenAddress != "127.0.0.1:2055" {
		t.Fatalf("fakeReceiver.cfg.ListenAddress = %q, want %q", fakeReceiver.cfg.ListenAddress, "127.0.0.1:2055")
	}
	if fakeReceiver.cfg.MaxDatagramSize != 4096 {
		t.Fatalf("fakeReceiver.cfg.MaxDatagramSize = %d, want %d", fakeReceiver.cfg.MaxDatagramSize, 4096)
	}
}

type fakeFlowReceiver struct {
	cfg     flowprotocol.ReceiveConfig
	emitter flowprotocol.EmitterConfig
}

func (r *fakeFlowReceiver) Run(ctx context.Context, cfg flowprotocol.ReceiveConfig, emitter flowprotocol.EmitterConfig, handle flowprotocol.BatchHandler) error {
	r.cfg = cfg
	r.emitter = emitter
	return handle(ctx, []observations.Observation{{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: "flow-obs-1",
		Type:          flowprotocol.ObservationType,
		Scope:         "sighting",
		SiteID:        emitter.SiteID,
		Emitter: &observations.Emitter{
			Kind:       "sensor",
			ID:         emitter.NodeID,
			Name:       emitter.Name,
			Version:    emitter.Version,
			Capability: "flow",
		},
		ObservedAt: time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC),
		Addresses:  &observations.Addresses{IPAddresses: []string{"10.0.0.10"}},
		Facts: map[string]any{
			"exporter_address": "192.0.2.10",
			"protocols":        []string{"tcp"},
		},
		Evidence: &observations.Evidence{Confidence: 0.45, SourceProtocol: "flow", FlowCount: 1},
	}})
}
