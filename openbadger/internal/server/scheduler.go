package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mbaybarsk/openbadger/internal/ops"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
)

const defaultSchedulerBatchSize = 16

type schedulerService struct {
	store                scheduleStore
	now                  func() time.Time
	batchSize            int
	observationRetention time.Duration
}

func newSchedulerService(store scheduleStore, now func() time.Time) *schedulerService {
	if now == nil {
		now = time.Now
	}

	return &schedulerService{store: store, now: now, batchSize: defaultSchedulerBatchSize}
}

func (s *schedulerService) WithObservationRetention(retention time.Duration) *schedulerService {
	if s == nil {
		return nil
	}

	s.observationRetention = retention
	return s
}

func (s *schedulerService) Run(ctx context.Context, interval time.Duration, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	if s == nil || s.store == nil {
		return errServiceUnavailable("scheduler")
	}

	if interval <= 0 {
		interval = time.Second
	}

	if _, err := s.RunOnce(ctx, logger); err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := s.RunOnce(ctx, logger); err != nil {
				return err
			}
		}
	}
}

func (s *schedulerService) RunOnce(ctx context.Context, logger *slog.Logger) (int, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if s == nil || s.store == nil {
		return 0, errServiceUnavailable("scheduler")
	}

	now := s.now().UTC()
	dueSchedules, err := s.store.ListDueSchedules(ctx, now, s.batchSize)
	if err != nil {
		return 0, fmt.Errorf("list due schedules: %w", err)
	}

	created := 0
	for _, due := range dueSchedules {
		payload, err := postgres.BuildScheduleJobPayload(due)
		if err != nil {
			return created, fmt.Errorf("build job payload for schedule %q: %w", due.Schedule.ID, err)
		}

		if _, err := s.store.CreateJob(ctx, postgres.CreateJobParams{
			SiteID:     due.Schedule.SiteID,
			Kind:       "scan",
			Capability: due.ScanProfile.Capability,
			Payload:    payload,
		}); err != nil {
			return created, fmt.Errorf("create job for schedule %q: %w", due.Schedule.ID, err)
		}

		nextRunAt, err := schedules.NextRun(due.Schedule.CronExpression, now)
		if err != nil {
			return created, fmt.Errorf("calculate next run for schedule %q: %w", due.Schedule.ID, err)
		}

		if _, err := s.store.MarkScheduleRun(ctx, postgres.UpdateScheduleRunParams{
			ScheduleID: due.Schedule.ID,
			RunAt:      now,
			NextRunAt:  nextRunAt,
		}); err != nil {
			return created, fmt.Errorf("mark schedule %q run: %w", due.Schedule.ID, err)
		}

		created++
		ops.ScheduledJobsCreatedTotal.Add(1)
		logger.Info("created scheduled job", "schedule_id", due.Schedule.ID, "capability", due.ScanProfile.Capability, "site_id", due.Schedule.SiteID)
	}

	if err := s.applyObservationRetention(ctx, now, logger); err != nil {
		return created, err
	}

	return created, nil
}

func (s *schedulerService) applyObservationRetention(ctx context.Context, now time.Time, logger *slog.Logger) error {
	retention := normalizeObservationRetention(s.observationRetention)
	if retention <= 0 {
		return nil
	}

	cutoff := now.Add(-retention)
	deleted, err := s.store.DeleteObservationsBefore(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("apply observation retention: %w", err)
	}

	ops.ObservationRetentionRunsTotal.Add(1)
	ops.ObservationsDeletedTotal.Add(deleted)
	if deleted > 0 {
		logger.Info("applied observation retention", "cutoff", cutoff, "deleted", deleted)
	}

	return nil
}

func normalizeObservationRetention(retention time.Duration) time.Duration {
	if retention < 0 {
		return 0
	}

	return retention
}
