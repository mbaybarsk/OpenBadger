package sensor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/mbaybarsk/openbadger/internal/config"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
	flowprotocol "github.com/mbaybarsk/openbadger/internal/protocols/flow"
	pcapprotocol "github.com/mbaybarsk/openbadger/internal/protocols/pcap"
	"github.com/mbaybarsk/openbadger/internal/version"
)

func Run(ctx context.Context, cfg config.SensorConfig, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	runner, err := newSensorRunner(cfg, logger)
	if err != nil {
		return err
	}

	return nodes.RunAgent(ctx, nodes.AgentConfig{
		Kind:              nodes.KindSensor,
		Name:              cfg.Name,
		ServerURL:         cfg.ServerURL,
		SiteID:            cfg.SiteID,
		EnrollmentToken:   cfg.EnrollmentToken,
		StatePath:         cfg.StatePath,
		Version:           version.Version,
		HeartbeatInterval: cfg.HeartbeatInterval,
		AfterHeartbeat: func(ctx context.Context, client *nodes.Client, state nodes.State) error {
			runner.Start(ctx, client, state)
			return nil
		},
	}, logger)
}

type sensorRunner struct {
	capture *captureRunner
	flow    *flowRunner
}

func newSensorRunner(cfg config.SensorConfig, logger *slog.Logger) (*sensorRunner, error) {
	runner := &sensorRunner{}
	if hasPCAPSource(cfg) {
		captureRunner, err := newCaptureRunner(cfg, logger)
		if err != nil {
			return nil, err
		}
		runner.capture = captureRunner
	}

	if hasFlowSource(cfg) {
		flowRunner, err := newFlowRunner(cfg, logger)
		if err != nil {
			return nil, err
		}
		runner.flow = flowRunner
	}

	if runner.capture == nil && runner.flow == nil {
		return nil, fmt.Errorf("sensor capture interface, pcap file, or flow listen address is required")
	}

	return runner, nil
}

func (r *sensorRunner) Start(ctx context.Context, client *nodes.Client, state nodes.State) {
	if r == nil {
		return
	}

	if r.capture != nil {
		r.capture.Start(ctx, client, state)
	}

	if r.flow != nil {
		r.flow.Start(ctx, client, state)
	}
}

type captureRunner struct {
	cfg       config.SensorConfig
	logger    *slog.Logger
	processor *pcapprotocol.WindowProcessor
	once      sync.Once
}

func newCaptureRunner(cfg config.SensorConfig, logger *slog.Logger) (*captureRunner, error) {
	if !hasPCAPSource(cfg) {
		return nil, fmt.Errorf("sensor capture interface or pcap file is required")
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &captureRunner{
		cfg:       cfg,
		logger:    logger,
		processor: pcapprotocol.NewWindowProcessor(),
	}, nil
}

func (r *captureRunner) Start(ctx context.Context, client *nodes.Client, state nodes.State) {
	if r == nil || client == nil {
		return
	}

	r.once.Do(func() {
		go r.loop(ctx, client, state)
	})
}

func (r *captureRunner) loop(ctx context.Context, client *nodes.Client, state nodes.State) {
	source := pcapprotocol.SourceConfig{
		Interface:   r.cfg.Interface,
		FilePath:    r.cfg.PCAPFile,
		SnapLen:     r.cfg.SnapLen,
		Promiscuous: r.cfg.Promiscuous,
		ReadTimeout: r.cfg.ReadTimeout,
	}

	emitter := pcapprotocol.EmitterConfig{
		SiteID:  state.SiteID,
		NodeID:  state.NodeID,
		Name:    state.Name,
		Version: version.Version,
	}

	offline := strings.TrimSpace(source.FilePath) != ""

	for {
		batch, err := r.processor.CaptureWindow(ctx, source, emitter, r.cfg.CaptureWindow)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			r.logger.Warn("pcap capture failed", "error", err, "interface", source.Interface, "pcap_file", source.FilePath)
			if offline {
				return
			}

			continue
		}

		if len(batch) > 0 {
			if _, err := client.UploadObservationBatch(ctx, state.AuthToken, observations.BatchRequest{Observations: batch}); err != nil {
				if ctx.Err() != nil {
					return
				}

				r.logger.Warn("upload passive observations failed", "error", err, "count", len(batch))
			} else {
				r.logger.Info("uploaded passive observations", "count", len(batch), "site_id", state.SiteID)
			}
		}

		if offline {
			return
		}
	}
}

type flowReceiver interface {
	Run(ctx context.Context, cfg flowprotocol.ReceiveConfig, emitter flowprotocol.EmitterConfig, handle flowprotocol.BatchHandler) error
}

type flowRunner struct {
	cfg      config.SensorConfig
	logger   *slog.Logger
	receiver flowReceiver
	once     sync.Once
}

func newFlowRunner(cfg config.SensorConfig, logger *slog.Logger) (*flowRunner, error) {
	if !hasFlowSource(cfg) {
		return nil, fmt.Errorf("sensor flow listen address is required")
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &flowRunner{
		cfg:      cfg,
		logger:   logger,
		receiver: flowprotocol.NewReceiver(nil),
	}, nil
}

func (r *flowRunner) Start(ctx context.Context, client *nodes.Client, state nodes.State) {
	if r == nil || client == nil {
		return
	}

	r.once.Do(func() {
		go r.loop(ctx, client, state)
	})
}

func (r *flowRunner) loop(ctx context.Context, client *nodes.Client, state nodes.State) {
	if r == nil || r.receiver == nil || client == nil {
		return
	}

	err := r.receiver.Run(ctx, flowprotocol.ReceiveConfig{
		ListenAddress:   r.cfg.FlowListenAddress,
		Window:          r.cfg.CaptureWindow,
		ReadTimeout:     r.cfg.FlowReadTimeout,
		MaxDatagramSize: r.cfg.FlowMaxDatagram,
	}, flowprotocol.EmitterConfig{
		SiteID:  state.SiteID,
		NodeID:  state.NodeID,
		Name:    state.Name,
		Version: version.Version,
	}, func(ctx context.Context, batch []observations.Observation) error {
		if len(batch) == 0 {
			return nil
		}

		if _, err := client.UploadObservationBatch(ctx, state.AuthToken, observations.BatchRequest{Observations: batch}); err != nil {
			if ctx.Err() == nil {
				r.logger.Warn("upload flow observations failed", "error", err, "count", len(batch), "listen_address", r.cfg.FlowListenAddress)
			}
			return nil
		}

		r.logger.Info("uploaded flow observations", "count", len(batch), "site_id", state.SiteID, "listen_address", r.cfg.FlowListenAddress)
		return nil
	})
	if err != nil && ctx.Err() == nil {
		r.logger.Warn("flow receiver failed", "error", err, "listen_address", r.cfg.FlowListenAddress)
	}
}

func hasPCAPSource(cfg config.SensorConfig) bool {
	return strings.TrimSpace(cfg.Interface) != "" || strings.TrimSpace(cfg.PCAPFile) != ""
}

func hasFlowSource(cfg config.SensorConfig) bool {
	return strings.TrimSpace(cfg.FlowListenAddress) != ""
}
