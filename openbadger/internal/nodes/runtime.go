package nodes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

type AgentConfig struct {
	Kind              Kind
	Name              string
	ServerURL         string
	SiteID            string
	EnrollmentToken   string
	StatePath         string
	Version           string
	HeartbeatInterval time.Duration
	HTTPClient        *http.Client
	AfterHeartbeat    func(ctx context.Context, client *Client, state State) error
}

func RunAgent(ctx context.Context, cfg AgentConfig, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	kind := NormalizeKind(string(cfg.Kind))
	if !ValidateKind(kind) {
		return fmt.Errorf("node kind %q is invalid", cfg.Kind)
	}

	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		return fmt.Errorf("node name is required")
	}

	serverURL := strings.TrimSpace(cfg.ServerURL)
	if serverURL == "" {
		return fmt.Errorf("node server url is required")
	}

	statePath := strings.TrimSpace(cfg.StatePath)
	if statePath == "" {
		return fmt.Errorf("node state path is required")
	}

	version := strings.TrimSpace(cfg.Version)
	if version == "" {
		return fmt.Errorf("node version is required")
	}

	client := NewClient(serverURL, cfg.HTTPClient)
	capabilities := DefaultCapabilities(kind)

	state, err := LoadState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		siteID := strings.TrimSpace(cfg.SiteID)
		if siteID == "" {
			return fmt.Errorf("node site id is required when state file does not exist")
		}

		bootstrapToken := strings.TrimSpace(cfg.EnrollmentToken)
		if bootstrapToken == "" {
			return fmt.Errorf("node enrollment token is required when state file does not exist")
		}

		enrollment, enrollErr := client.Enroll(ctx, bootstrapToken, EnrollRequest{
			SiteID:       siteID,
			Kind:         kind,
			Name:         name,
			Version:      version,
			Capabilities: capabilities,
		})
		if enrollErr != nil {
			return fmt.Errorf("enroll node: %w", enrollErr)
		}

		state = State{
			NodeID:    enrollment.NodeID,
			SiteID:    enrollment.SiteID,
			Kind:      enrollment.Kind,
			Name:      enrollment.Name,
			AuthToken: enrollment.AuthToken,
		}

		if err := SaveState(statePath, state); err != nil {
			return fmt.Errorf("persist node state: %w", err)
		}

		logger.Info("node enrolled", "mode", string(kind), "node_id", state.NodeID, "site_id", state.SiteID, "state_path", statePath)
	} else if err != nil {
		return fmt.Errorf("load node state: %w", err)
	}

	if NormalizeKind(string(state.Kind)) != kind {
		return fmt.Errorf("node state kind %q does not match runtime kind %q", state.Kind, kind)
	}

	heartbeat := func() error {
		_, err := client.Heartbeat(ctx, state.AuthToken, HeartbeatRequest{
			Name:         name,
			Version:      version,
			Capabilities: capabilities,
			HealthStatus: "healthy",
		})
		if err != nil {
			return fmt.Errorf("send node heartbeat: %w", err)
		}

		if state.Name != name {
			state.Name = name
			if err := SaveState(statePath, state); err != nil {
				return fmt.Errorf("persist node state: %w", err)
			}
		}

		return nil
	}

	if err := heartbeat(); err != nil {
		return err
	}

	logger.Info("starting mode", "mode", string(kind), "name", name, "node_id", state.NodeID, "server_url", serverURL)

	if cfg.AfterHeartbeat != nil {
		if err := cfg.AfterHeartbeat(ctx, client, state); err != nil {
			logger.Warn("node cycle hook failed", "mode", string(kind), "node_id", state.NodeID, "error", err)
		}
	}

	interval := cfg.HeartbeatInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("stopping mode", "mode", string(kind), "name", name, "node_id", state.NodeID, "reason", ctx.Err())
			return nil
		case <-ticker.C:
			if err := heartbeat(); err != nil {
				logger.Warn("node heartbeat failed", "mode", string(kind), "node_id", state.NodeID, "error", err)
				continue
			}

			if cfg.AfterHeartbeat != nil {
				if err := cfg.AfterHeartbeat(ctx, client, state); err != nil {
					logger.Warn("node cycle hook failed", "mode", string(kind), "node_id", state.NodeID, "error", err)
				}
			}
		}
	}
}
