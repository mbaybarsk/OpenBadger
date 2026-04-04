package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mbaybarsk/openbadger/internal/config"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
	"github.com/mbaybarsk/openbadger/internal/version"
)

func Run(ctx context.Context, cfg config.CollectorConfig, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	runners := newRunnerRegistry(
		newDemoRunner(nil),
		newICMPRunner(nil, nil),
		newSNMPRunner(nil, nil),
		newSSHRunner(nil, nil),
		newWinRMRunner(nil, nil),
	)

	return nodes.RunAgent(ctx, nodes.AgentConfig{
		Kind:              nodes.KindCollector,
		Name:              cfg.Name,
		ServerURL:         cfg.ServerURL,
		SiteID:            cfg.SiteID,
		EnrollmentToken:   cfg.EnrollmentToken,
		StatePath:         cfg.StatePath,
		Version:           version.Version,
		HeartbeatInterval: cfg.HeartbeatInterval,
		AfterHeartbeat: func(ctx context.Context, client *nodes.Client, state nodes.State) error {
			job, leased, err := client.LeaseJob(ctx, state.AuthToken, jobtypes.LeaseRequest{LeaseDurationSeconds: 30})
			if err != nil {
				return fmt.Errorf("lease job: %w", err)
			}

			if !leased {
				return nil
			}

			logger.Info("accepted leased job", "job_id", job.ID, "capability", job.Capability, "kind", job.Kind)

			runner := selectRunner(job, runners)
			if runner != nil {
				results, err := runner.Run(ctx, RunRequest{
					Job:     job,
					Node:    state,
					Version: version.Version,
				})
				if err != nil {
					return failJob(ctx, client, state.AuthToken, job.ID, fmt.Errorf("run collector job: %w", err))
				}

				if len(results) > 0 {
					if _, err := client.UploadObservationBatch(ctx, state.AuthToken, observations.BatchRequest{Observations: results}); err != nil {
						return failJob(ctx, client, state.AuthToken, job.ID, fmt.Errorf("upload observation batch: %w", err))
					}

					logger.Info("uploaded observations", "job_id", job.ID, "count", len(results))
				}
			}

			if _, err := client.UpdateJobStatus(ctx, state.AuthToken, job.ID, jobtypes.StatusRequest{Status: jobtypes.StatusSuccess}); err != nil {
				return fmt.Errorf("report job status: %w", err)
			}

			logger.Info("completed job", "job_id", job.ID, "status", jobtypes.StatusSuccess)
			return nil
		},
	}, logger)
}

func selectRunner(job jobtypes.Record, registry runnerRegistry) Runner {
	return registry.Select(job)
}

func failJob(ctx context.Context, client *nodes.Client, authToken string, jobID string, runErr error) error {
	summary := strings.TrimSpace(runErr.Error())
	if len(summary) > 240 {
		summary = summary[:240]
	}

	if _, err := client.UpdateJobStatus(ctx, authToken, jobID, jobtypes.StatusRequest{
		Status:       jobtypes.StatusFailed,
		ErrorSummary: summary,
	}); err != nil {
		return fmt.Errorf("%w: report failed job status: %v", runErr, err)
	}

	return runErr
}
