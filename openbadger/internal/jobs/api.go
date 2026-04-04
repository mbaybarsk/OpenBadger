package jobs

import "encoding/json"

type LeaseRequest struct {
	LeaseDurationSeconds int `json:"lease_duration_seconds,omitempty"`
}

type LeaseResponse struct {
	Job Record `json:"job"`
}

type StatusRequest struct {
	Status       Status `json:"status"`
	ErrorSummary string `json:"error_summary,omitempty"`
}

type StatusResponse struct {
	Job Record `json:"job"`
}

type DebugCreateRequest struct {
	SiteID     string          `json:"site_id"`
	Kind       string          `json:"kind,omitempty"`
	Capability string          `json:"capability"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type DebugCreateResponse struct {
	Job Record `json:"job"`
}
