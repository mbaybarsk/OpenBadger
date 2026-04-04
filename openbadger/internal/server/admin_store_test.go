package server

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

func (s *memoryNodeStore) CreateCredentialProfile(_ context.Context, params credentials.CreateRequest) (credentials.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := credentials.ValidateCreateRequest(params); err != nil {
		return credentials.Profile{}, err
	}

	s.credentialProfileSequence++
	now := time.Date(2026, time.April, 4, 9, 40, 30, 0, time.UTC)
	record := credentials.Profile{
		ID:        fmt.Sprintf("credential-profile-%d", s.credentialProfileSequence),
		SiteID:    strings.TrimSpace(params.SiteID),
		Name:      strings.TrimSpace(params.Name),
		Protocol:  credentials.NormalizeProtocol(params.Protocol),
		SNMP:      credentials.CloneSNMPProfile(params.SNMP),
		SSH:       credentials.CloneSSHProfile(params.SSH),
		WinRM:     credentials.CloneWinRMProfile(params.WinRM),
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.credentialProfilesByID[record.ID] = record
	return record, nil
}

func (s *memoryNodeStore) CreateTargetRange(_ context.Context, params targets.CreateRequest) (targets.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.targetRangeSequence++
	now := time.Date(2026, time.April, 4, 9, 40, 0, 0, time.UTC)
	record := targets.Record{
		ID:         fmt.Sprintf("target-range-%d", s.targetRangeSequence),
		SiteID:     strings.TrimSpace(params.SiteID),
		Name:       strings.TrimSpace(params.Name),
		CIDR:       strings.TrimSpace(params.CIDR),
		Exclusions: append([]string(nil), params.Exclusions...),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	s.targetRangesByID[record.ID] = record
	return record, nil
}

func (s *memoryNodeStore) CreateScanProfile(_ context.Context, params profiles.CreateScanProfileRequest) (profiles.ScanProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scanProfileSequence++
	now := time.Date(2026, time.April, 4, 9, 41, 0, 0, time.UTC)
	concurrency := params.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	timeoutMS := params.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 1000
	}
	record := profiles.ScanProfile{
		ID:                  fmt.Sprintf("scan-profile-%d", s.scanProfileSequence),
		SiteID:              strings.TrimSpace(params.SiteID),
		Name:                strings.TrimSpace(params.Name),
		Capability:          strings.ToLower(strings.TrimSpace(params.Capability)),
		TimeoutMS:           timeoutMS,
		RetryCount:          params.RetryCount,
		Concurrency:         concurrency,
		RateLimitPerMinute:  params.RateLimitPerMinute,
		CredentialProfileID: params.CredentialProfileID,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if (record.Capability == "snmp" || record.Capability == "ssh" || record.Capability == "winrm") && (record.CredentialProfileID == nil || strings.TrimSpace(*record.CredentialProfileID) == "") {
		return profiles.ScanProfile{}, fmt.Errorf("scan profile credential profile id is required for capability %q", record.Capability)
	}

	s.scanProfilesByID[record.ID] = record
	return record, nil
}

func (s *memoryNodeStore) CreateSchedule(_ context.Context, params schedules.CreateRequest) (schedules.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scheduleSequence++
	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Date(2026, time.April, 4, 9, 42, 0, 0, time.UTC)
	}

	nextRunAt, err := schedules.NextRun(params.CronExpression, now)
	if err != nil {
		return schedules.Record{}, err
	}

	record := schedules.Record{
		ID:             fmt.Sprintf("schedule-%d", s.scheduleSequence),
		SiteID:         strings.TrimSpace(params.SiteID),
		Name:           strings.TrimSpace(params.Name),
		CronExpression: strings.TrimSpace(params.CronExpression),
		TargetRangeID:  strings.TrimSpace(params.TargetRangeID),
		ScanProfileID:  strings.TrimSpace(params.ScanProfileID),
		Enabled:        schedules.EnabledValue(params.Enabled),
		NextRunAt:      nextRunAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	s.schedulesByID[record.ID] = record
	return record, nil
}

func (s *memoryNodeStore) ListDueSchedules(_ context.Context, now time.Time, _ int) ([]postgres.DueSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	due := make([]postgres.DueSchedule, 0)
	for _, scheduleRecord := range s.schedulesByID {
		if !scheduleRecord.Enabled || scheduleRecord.NextRunAt.After(now) {
			continue
		}

		targetRange, ok := s.targetRangesByID[scheduleRecord.TargetRangeID]
		if !ok {
			continue
		}

		scanProfile, ok := s.scanProfilesByID[scheduleRecord.ScanProfileID]
		if !ok {
			continue
		}

		due = append(due, postgres.DueSchedule{
			Schedule:    scheduleRecord,
			TargetRange: targetRange,
			ScanProfile: scanProfile,
		})

		if scanProfile.CredentialProfileID != nil {
			credentialProfile, ok := s.credentialProfilesByID[strings.TrimSpace(*scanProfile.CredentialProfileID)]
			if ok {
				copy := credentialProfile
				due[len(due)-1].CredentialProfile = &copy
			}
		}
	}

	sort.Slice(due, func(i, j int) bool {
		return due[i].Schedule.NextRunAt.Before(due[j].Schedule.NextRunAt)
	})

	return due, nil
}

func (s *memoryNodeStore) MarkScheduleRun(_ context.Context, params postgres.UpdateScheduleRunParams) (schedules.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.schedulesByID[strings.TrimSpace(params.ScheduleID)]
	runAt := params.RunAt.UTC()
	record.LastRunAt = timeRef(runAt)
	record.NextRunAt = params.NextRunAt.UTC()
	record.UpdatedAt = runAt
	s.schedulesByID[record.ID] = record
	return record, nil
}

func newScheduledMemoryStore() *memoryNodeStore {
	return newMemoryNodeStore()
}

func (s *memoryNodeStore) jobCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jobsByID)
}

func (s *memoryNodeStore) firstJobByCapability(capability string) (jobtypes.Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, jobID := range s.jobOrder {
		job := s.jobsByID[jobID]
		if job.Capability == capability {
			return job, true
		}
	}
	return jobtypes.Record{}, false
}
