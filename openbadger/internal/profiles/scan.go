package profiles

import "time"

type ScanProfile struct {
	ID                  string    `json:"id"`
	SiteID              string    `json:"site_id"`
	Name                string    `json:"name"`
	Capability          string    `json:"capability"`
	TimeoutMS           int       `json:"timeout_ms"`
	RetryCount          int       `json:"retry_count"`
	Concurrency         int       `json:"concurrency"`
	RateLimitPerMinute  int       `json:"rate_limit_per_minute,omitempty"`
	CredentialProfileID *string   `json:"credential_profile_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type CreateScanProfileRequest struct {
	SiteID              string  `json:"site_id"`
	Name                string  `json:"name"`
	Capability          string  `json:"capability"`
	TimeoutMS           int     `json:"timeout_ms,omitempty"`
	RetryCount          int     `json:"retry_count,omitempty"`
	Concurrency         int     `json:"concurrency,omitempty"`
	RateLimitPerMinute  int     `json:"rate_limit_per_minute,omitempty"`
	CredentialProfileID *string `json:"credential_profile_id,omitempty"`
}

type DebugCreateScanProfileResponse struct {
	ScanProfile ScanProfile `json:"scan_profile"`
}
