package schedules

import (
	"fmt"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/targets"
	cron "github.com/robfig/cron/v3"
)

var expressionParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

type Record struct {
	ID             string     `json:"id"`
	SiteID         string     `json:"site_id"`
	Name           string     `json:"name"`
	CronExpression string     `json:"cron_expression"`
	TargetRangeID  string     `json:"target_range_id"`
	ScanProfileID  string     `json:"scan_profile_id"`
	Enabled        bool       `json:"enabled"`
	NextRunAt      time.Time  `json:"next_run_at"`
	LastRunAt      *time.Time `json:"last_run_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type CreateRequest struct {
	SiteID         string    `json:"site_id"`
	Name           string    `json:"name"`
	CronExpression string    `json:"cron_expression"`
	TargetRangeID  string    `json:"target_range_id"`
	ScanProfileID  string    `json:"scan_profile_id"`
	Enabled        *bool     `json:"enabled,omitempty"`
	Now            time.Time `json:"-"`
}

type DebugCreateResponse struct {
	Schedule Record `json:"schedule"`
}

type DueRecord struct {
	Schedule          Record               `json:"schedule"`
	TargetRange       targets.Record       `json:"target_range"`
	ScanProfile       profiles.ScanProfile `json:"scan_profile"`
	CredentialProfile *credentials.Profile `json:"credential_profile,omitempty"`
}

func ParseExpression(expression string) (cron.Schedule, error) {
	normalized := strings.Join(strings.Fields(strings.TrimSpace(expression)), " ")
	if normalized == "" {
		return nil, fmt.Errorf("schedule expression is required")
	}

	schedule, err := expressionParser.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("schedule expression %q is invalid: %w", expression, err)
	}

	return schedule, nil
}

func NextRun(expression string, from time.Time) (time.Time, error) {
	schedule, err := ParseExpression(expression)
	if err != nil {
		return time.Time{}, err
	}

	if from.IsZero() {
		from = time.Now().UTC()
	} else {
		from = from.UTC()
	}

	return schedule.Next(from), nil
}

func EnabledValue(value *bool) bool {
	if value == nil {
		return true
	}

	return *value
}
