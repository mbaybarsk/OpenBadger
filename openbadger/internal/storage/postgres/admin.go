package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mbaybarsk/openbadger/internal/credentials"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

type TargetRange = targets.Record

type CreateTargetRangeParams = targets.CreateRequest

type CredentialProfile = credentials.Profile

type CreateCredentialProfileParams = credentials.CreateRequest

type ScanProfile = profiles.ScanProfile

type CreateScanProfileParams = profiles.CreateScanProfileRequest

type Schedule = schedules.Record

type CreateScheduleParams = schedules.CreateRequest

type DueSchedule = schedules.DueRecord

type UpdateScheduleRunParams struct {
	ScheduleID string
	RunAt      time.Time
	NextRunAt  time.Time
}

func (r *Repository) CreateTargetRange(ctx context.Context, params CreateTargetRangeParams) (TargetRange, error) {
	if r == nil || r.db == nil {
		return TargetRange{}, fmt.Errorf("repository database is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return TargetRange{}, fmt.Errorf("target range site id is required")
	}

	name := strings.TrimSpace(params.Name)
	if name == "" {
		return TargetRange{}, fmt.Errorf("target range name is required")
	}

	cidr, err := targets.NormalizeCIDR(params.CIDR)
	if err != nil {
		return TargetRange{}, fmt.Errorf("target range %w", err)
	}

	exclusions, err := targets.NormalizeExclusions(params.Exclusions)
	if err != nil {
		return TargetRange{}, fmt.Errorf("target range %w", err)
	}

	exclusionsJSON, err := json.Marshal(exclusions)
	if err != nil {
		return TargetRange{}, fmt.Errorf("marshal target range exclusions: %w", err)
	}

	record := TargetRange{
		ID:         uuid.NewString(),
		SiteID:     siteID,
		Name:       name,
		CIDR:       cidr,
		Exclusions: exclusions,
	}

	err = r.db.QueryRow(ctx, `
		INSERT INTO target_ranges (id, site_id, name, cidr, exclusions)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`, record.ID, record.SiteID, record.Name, record.CIDR, exclusionsJSON).Scan(&record.CreatedAt, &record.UpdatedAt)
	if err != nil {
		return TargetRange{}, fmt.Errorf("insert target range: %w", err)
	}

	return record, nil
}

func (r *Repository) CreateCredentialProfile(ctx context.Context, params CreateCredentialProfileParams) (CredentialProfile, error) {
	if r == nil || r.db == nil {
		return CredentialProfile{}, fmt.Errorf("repository database is required")
	}

	if err := credentials.ValidateCreateRequest(params); err != nil {
		return CredentialProfile{}, err
	}

	record := CredentialProfile{
		ID:       uuid.NewString(),
		SiteID:   strings.TrimSpace(params.SiteID),
		Name:     strings.TrimSpace(params.Name),
		Protocol: credentials.NormalizeProtocol(params.Protocol),
		SNMP:     credentials.CloneSNMPProfile(params.SNMP),
		SSH:      credentials.CloneSSHProfile(params.SSH),
		WinRM:    credentials.CloneWinRMProfile(params.WinRM),
	}

	var payload any
	switch record.Protocol {
	case credentials.ProtocolSNMP:
		payload = record.SNMP
	case credentials.ProtocolSSH:
		payload = record.SSH
	case credentials.ProtocolWinRM:
		payload = record.WinRM
	default:
		return CredentialProfile{}, fmt.Errorf("credential profile protocol %q is invalid", record.Protocol)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return CredentialProfile{}, fmt.Errorf("marshal credential profile payload: %w", err)
	}

	storedPayloadJSON, err := r.encryptJSONPayload(payloadJSON)
	if err != nil {
		return CredentialProfile{}, err
	}

	err = r.db.QueryRow(ctx, `
		INSERT INTO credential_profiles (id, site_id, name, protocol, payload)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`, record.ID, record.SiteID, record.Name, record.Protocol, storedPayloadJSON).Scan(&record.CreatedAt, &record.UpdatedAt)
	if err != nil {
		return CredentialProfile{}, fmt.Errorf("insert credential profile: %w", err)
	}

	return record, nil
}

func (r *Repository) CreateScanProfile(ctx context.Context, params CreateScanProfileParams) (ScanProfile, error) {
	if r == nil || r.db == nil {
		return ScanProfile{}, fmt.Errorf("repository database is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return ScanProfile{}, fmt.Errorf("scan profile site id is required")
	}

	name := strings.TrimSpace(params.Name)
	if name == "" {
		return ScanProfile{}, fmt.Errorf("scan profile name is required")
	}

	capability := strings.ToLower(strings.TrimSpace(params.Capability))
	if capability == "" {
		return ScanProfile{}, fmt.Errorf("scan profile capability is required")
	}

	timeoutMS := params.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 1000
	}

	if params.RetryCount < 0 {
		return ScanProfile{}, fmt.Errorf("scan profile retry count is invalid")
	}

	concurrency := params.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	if params.RateLimitPerMinute < 0 {
		return ScanProfile{}, fmt.Errorf("scan profile rate limit is invalid")
	}

	credentialProfileID := trimOptionalStringPointer(params.CredentialProfileID)
	if (capability == "snmp" || capability == "ssh" || capability == "winrm") && credentialProfileID == nil {
		return ScanProfile{}, fmt.Errorf("scan profile credential profile id is required for capability %q", capability)
	}

	record := ScanProfile{
		ID:                  uuid.NewString(),
		SiteID:              siteID,
		Name:                name,
		Capability:          capability,
		TimeoutMS:           timeoutMS,
		RetryCount:          params.RetryCount,
		Concurrency:         concurrency,
		RateLimitPerMinute:  params.RateLimitPerMinute,
		CredentialProfileID: credentialProfileID,
	}

	err := r.db.QueryRow(ctx, `
		INSERT INTO scan_profiles (id, site_id, name, capability, timeout_ms, retry_count, concurrency, rate_limit_per_minute, credential_profile_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at, updated_at
	`, record.ID, record.SiteID, record.Name, record.Capability, record.TimeoutMS, record.RetryCount, record.Concurrency, record.RateLimitPerMinute, record.CredentialProfileID).Scan(&record.CreatedAt, &record.UpdatedAt)
	if err != nil {
		return ScanProfile{}, fmt.Errorf("insert scan profile: %w", err)
	}

	return record, nil
}

func (r *Repository) CreateSchedule(ctx context.Context, params CreateScheduleParams) (Schedule, error) {
	if r == nil || r.db == nil {
		return Schedule{}, fmt.Errorf("repository database is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return Schedule{}, fmt.Errorf("schedule site id is required")
	}

	name := strings.TrimSpace(params.Name)
	if name == "" {
		return Schedule{}, fmt.Errorf("schedule name is required")
	}

	cronExpression := strings.TrimSpace(params.CronExpression)
	if cronExpression == "" {
		return Schedule{}, fmt.Errorf("schedule cron expression is required")
	}

	targetRangeID := strings.TrimSpace(params.TargetRangeID)
	if targetRangeID == "" {
		return Schedule{}, fmt.Errorf("schedule target range id is required")
	}

	scanProfileID := strings.TrimSpace(params.ScanProfileID)
	if scanProfileID == "" {
		return Schedule{}, fmt.Errorf("schedule scan profile id is required")
	}

	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	nextRunAt, err := schedules.NextRun(cronExpression, now)
	if err != nil {
		return Schedule{}, err
	}

	record := Schedule{
		ID:             uuid.NewString(),
		SiteID:         siteID,
		Name:           name,
		CronExpression: cronExpression,
		TargetRangeID:  targetRangeID,
		ScanProfileID:  scanProfileID,
		Enabled:        schedules.EnabledValue(params.Enabled),
		NextRunAt:      nextRunAt,
	}

	err = r.db.QueryRow(ctx, `
		INSERT INTO schedules (id, site_id, name, cron_expression, target_range_id, scan_profile_id, enabled, next_run_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at
	`, record.ID, record.SiteID, record.Name, record.CronExpression, record.TargetRangeID, record.ScanProfileID, record.Enabled, record.NextRunAt).Scan(&record.CreatedAt, &record.UpdatedAt)
	if err != nil {
		return Schedule{}, fmt.Errorf("insert schedule: %w", err)
	}

	return record, nil
}

func (r *Repository) ListDueSchedules(ctx context.Context, now time.Time, limit int) ([]DueSchedule, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if limit <= 0 {
		limit = 16
	}

	rows, err := r.db.Query(ctx, `
		SELECT
			s.id, s.site_id, s.name, s.cron_expression, s.target_range_id, s.scan_profile_id, s.enabled, s.next_run_at, s.last_run_at, s.created_at, s.updated_at,
			tr.id, tr.site_id, tr.name, tr.cidr, tr.exclusions, tr.created_at, tr.updated_at,
			sp.id, sp.site_id, sp.name, sp.capability, sp.timeout_ms, sp.retry_count, sp.concurrency, sp.rate_limit_per_minute, sp.credential_profile_id, sp.created_at, sp.updated_at,
			cp.id, cp.site_id, cp.name, cp.protocol, cp.payload, cp.created_at, cp.updated_at
		FROM schedules AS s
		JOIN target_ranges AS tr ON tr.id = s.target_range_id
		JOIN scan_profiles AS sp ON sp.id = s.scan_profile_id
		LEFT JOIN credential_profiles AS cp ON cp.id = sp.credential_profile_id
		WHERE s.enabled = TRUE AND s.next_run_at <= $1
		ORDER BY s.next_run_at ASC, s.created_at ASC, s.id ASC
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list due schedules: %w", err)
	}
	defer rows.Close()

	result := make([]DueSchedule, 0)
	for rows.Next() {
		var due DueSchedule
		var exclusionsJSON []byte
		var credentialProfileID *string
		var credentialSiteID *string
		var credentialName *string
		var credentialProtocol *string
		var credentialPayloadJSON []byte
		var credentialCreatedAt *time.Time
		var credentialUpdatedAt *time.Time
		if err := rows.Scan(
			&due.Schedule.ID,
			&due.Schedule.SiteID,
			&due.Schedule.Name,
			&due.Schedule.CronExpression,
			&due.Schedule.TargetRangeID,
			&due.Schedule.ScanProfileID,
			&due.Schedule.Enabled,
			&due.Schedule.NextRunAt,
			&due.Schedule.LastRunAt,
			&due.Schedule.CreatedAt,
			&due.Schedule.UpdatedAt,
			&due.TargetRange.ID,
			&due.TargetRange.SiteID,
			&due.TargetRange.Name,
			&due.TargetRange.CIDR,
			&exclusionsJSON,
			&due.TargetRange.CreatedAt,
			&due.TargetRange.UpdatedAt,
			&due.ScanProfile.ID,
			&due.ScanProfile.SiteID,
			&due.ScanProfile.Name,
			&due.ScanProfile.Capability,
			&due.ScanProfile.TimeoutMS,
			&due.ScanProfile.RetryCount,
			&due.ScanProfile.Concurrency,
			&due.ScanProfile.RateLimitPerMinute,
			&due.ScanProfile.CredentialProfileID,
			&due.ScanProfile.CreatedAt,
			&due.ScanProfile.UpdatedAt,
			&credentialProfileID,
			&credentialSiteID,
			&credentialName,
			&credentialProtocol,
			&credentialPayloadJSON,
			&credentialCreatedAt,
			&credentialUpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan due schedule: %w", err)
		}

		if len(exclusionsJSON) > 0 {
			if err := json.Unmarshal(exclusionsJSON, &due.TargetRange.Exclusions); err != nil {
				return nil, fmt.Errorf("decode target range exclusions: %w", err)
			}
		}

		if credentialProfileID != nil {
			profile := credentials.Profile{
				ID:       strings.TrimSpace(*credentialProfileID),
				Protocol: credentials.NormalizeProtocol(valueOrEmpty(credentialProtocol)),
			}
			if credentialSiteID != nil {
				profile.SiteID = strings.TrimSpace(*credentialSiteID)
			}
			if credentialName != nil {
				profile.Name = strings.TrimSpace(*credentialName)
			}
			if credentialCreatedAt != nil {
				profile.CreatedAt = credentialCreatedAt.UTC()
			}
			if credentialUpdatedAt != nil {
				profile.UpdatedAt = credentialUpdatedAt.UTC()
			}

			if len(credentialPayloadJSON) > 0 {
				credentialPayloadJSON, err = r.decryptJSONPayload(credentialPayloadJSON)
				if err != nil {
					return nil, fmt.Errorf("decrypt credential profile payload: %w", err)
				}

				switch profile.Protocol {
				case credentials.ProtocolSNMP:
					var snmpProfile credentials.SNMPProfile
					if err := json.Unmarshal(credentialPayloadJSON, &snmpProfile); err != nil {
						return nil, fmt.Errorf("decode credential profile payload: %w", err)
					}
					profile.SNMP = &snmpProfile
				case credentials.ProtocolSSH:
					var sshProfile credentials.SSHProfile
					if err := json.Unmarshal(credentialPayloadJSON, &sshProfile); err != nil {
						return nil, fmt.Errorf("decode credential profile payload: %w", err)
					}
					profile.SSH = &sshProfile
				case credentials.ProtocolWinRM:
					var winrmProfile credentials.WinRMProfile
					if err := json.Unmarshal(credentialPayloadJSON, &winrmProfile); err != nil {
						return nil, fmt.Errorf("decode credential profile payload: %w", err)
					}
					profile.WinRM = &winrmProfile
				}
			}

			due.CredentialProfile = &profile
		}

		result = append(result, due)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due schedules: %w", err)
	}

	return result, nil
}

func (r *Repository) ListSchedules(ctx context.Context, limit int) ([]Schedule, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, site_id, name, cron_expression, target_range_id, scan_profile_id, enabled, next_run_at, last_run_at, created_at, updated_at
		FROM schedules
		ORDER BY next_run_at ASC, created_at ASC, id ASC
		LIMIT $1
	`, normalizeScheduleListLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	defer rows.Close()

	result := make([]Schedule, 0)
	for rows.Next() {
		record, err := scanScheduleRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan schedule: %w", err)
		}

		result = append(result, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schedules: %w", err)
	}

	return result, nil
}

func (r *Repository) MarkScheduleRun(ctx context.Context, params UpdateScheduleRunParams) (Schedule, error) {
	if r == nil || r.db == nil {
		return Schedule{}, fmt.Errorf("repository database is required")
	}

	scheduleID := strings.TrimSpace(params.ScheduleID)
	if scheduleID == "" {
		return Schedule{}, fmt.Errorf("schedule id is required")
	}

	runAt := params.RunAt.UTC()
	if runAt.IsZero() {
		runAt = time.Now().UTC()
	}

	if params.NextRunAt.IsZero() {
		return Schedule{}, fmt.Errorf("schedule next run at is required")
	}

	record, err := scanScheduleRow(r.db.QueryRow(ctx, `
		UPDATE schedules
		SET last_run_at = $2,
			next_run_at = $3,
			updated_at = $2
		WHERE id = $1
		RETURNING id, site_id, name, cron_expression, target_range_id, scan_profile_id, enabled, next_run_at, last_run_at, created_at, updated_at
	`, scheduleID, runAt, params.NextRunAt.UTC()))
	if err != nil {
		return Schedule{}, fmt.Errorf("update schedule run: %w", err)
	}

	return record, nil
}

type scheduleRowScanner interface {
	Scan(dest ...any) error
}

func scanScheduleRow(row scheduleRowScanner) (Schedule, error) {
	var record Schedule
	err := row.Scan(
		&record.ID,
		&record.SiteID,
		&record.Name,
		&record.CronExpression,
		&record.TargetRangeID,
		&record.ScanProfileID,
		&record.Enabled,
		&record.NextRunAt,
		&record.LastRunAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return Schedule{}, err
	}

	return record, nil
}

func normalizeScheduleListLimit(limit int) int {
	if limit <= 0 {
		return 100
	}

	if limit > 500 {
		return 500
	}

	return limit
}

func BuildScheduleJobPayload(due DueSchedule) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(due.ScanProfile.Capability)) {
	case "icmp":
		return json.Marshal(jobtypes.ICMPScanPayload{
			Targets: []jobtypes.ICMPScanTarget{{
				CIDR:       due.TargetRange.CIDR,
				Exclusions: append([]string(nil), due.TargetRange.Exclusions...),
			}},
			TimeoutMS: due.ScanProfile.TimeoutMS,
		})
	case "snmp":
		if due.CredentialProfile == nil || due.CredentialProfile.SNMP == nil {
			return nil, fmt.Errorf("snmp schedule credential profile is required")
		}

		payload := jobtypes.SNMPScanPayload{
			Targets: []jobtypes.SNMPScanTarget{{
				CIDR:       due.TargetRange.CIDR,
				Exclusions: append([]string(nil), due.TargetRange.Exclusions...),
			}},
			TimeoutMS:         due.ScanProfile.TimeoutMS,
			RetryCount:        due.ScanProfile.RetryCount,
			CredentialProfile: credentials.CloneProfile(due.CredentialProfile),
		}

		if due.ScanProfile.CredentialProfileID != nil {
			payload.CredentialProfileID = strings.TrimSpace(*due.ScanProfile.CredentialProfileID)
		}

		if payload.CredentialProfile != nil && payload.CredentialProfile.SNMP != nil {
			payload.Port = credentials.DefaultSNMPPort(payload.CredentialProfile.SNMP.Port)
		}

		return json.Marshal(payload)
	case "ssh":
		if due.CredentialProfile == nil || due.CredentialProfile.SSH == nil {
			return nil, fmt.Errorf("ssh schedule credential profile is required")
		}

		payload := jobtypes.SSHScanPayload{
			Targets: []jobtypes.SSHScanTarget{{
				CIDR:       due.TargetRange.CIDR,
				Exclusions: append([]string(nil), due.TargetRange.Exclusions...),
			}},
			TimeoutMS:         due.ScanProfile.TimeoutMS,
			CredentialProfile: credentials.CloneProfile(due.CredentialProfile),
		}

		if due.ScanProfile.CredentialProfileID != nil {
			payload.CredentialProfileID = strings.TrimSpace(*due.ScanProfile.CredentialProfileID)
		}

		if payload.CredentialProfile != nil && payload.CredentialProfile.SSH != nil {
			payload.Port = credentials.DefaultSSHPort(payload.CredentialProfile.SSH.Port)
		}

		return json.Marshal(payload)
	case "winrm":
		if due.CredentialProfile == nil || due.CredentialProfile.WinRM == nil {
			return nil, fmt.Errorf("winrm schedule credential profile is required")
		}

		payload := jobtypes.WinRMScanPayload{
			Targets: []jobtypes.WinRMScanTarget{{
				CIDR:       due.TargetRange.CIDR,
				Exclusions: append([]string(nil), due.TargetRange.Exclusions...),
			}},
			TimeoutMS:         due.ScanProfile.TimeoutMS,
			CredentialProfile: credentials.CloneProfile(due.CredentialProfile),
		}

		if due.ScanProfile.CredentialProfileID != nil {
			payload.CredentialProfileID = strings.TrimSpace(*due.ScanProfile.CredentialProfileID)
		}

		if payload.CredentialProfile != nil && payload.CredentialProfile.WinRM != nil {
			payload.Port = credentials.DefaultWinRMPort(payload.CredentialProfile.WinRM.Port, credentials.WinRMUsesHTTPS(payload.CredentialProfile.WinRM))
		}

		return json.Marshal(payload)
	default:
		return json.Marshal(map[string]any{
			"capability": strings.ToLower(strings.TrimSpace(due.ScanProfile.Capability)),
		})
	}
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}
