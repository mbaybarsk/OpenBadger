package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound           = errors.New("job not found")
	ErrInvalidTransition  = errors.New("job invalid transition")
	ErrLeaseUnavailable   = errors.New("job lease unavailable")
	ErrLeaseOwnerMismatch = errors.New("job lease owner mismatch")
)

type Status string

const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

type Record struct {
	ID               string          `json:"id"`
	SiteID           string          `json:"site_id"`
	NodeID           *string         `json:"node_id,omitempty"`
	Kind             string          `json:"kind"`
	Capability       string          `json:"capability"`
	Payload          json.RawMessage `json:"payload,omitempty"`
	Status           Status          `json:"status"`
	LeaseOwnerNodeID *string         `json:"lease_owner_node_id,omitempty"`
	LeaseExpiresAt   *time.Time      `json:"lease_expires_at,omitempty"`
	ErrorSummary     string          `json:"error_summary,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	StartedAt        *time.Time      `json:"started_at,omitempty"`
	CompletedAt      *time.Time      `json:"completed_at,omitempty"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

func NormalizeStatus(value string) Status {
	return Status(strings.ToLower(strings.TrimSpace(value)))
}

func ValidateStatus(status Status) bool {
	switch NormalizeStatus(string(status)) {
	case StatusQueued, StatusRunning, StatusSuccess, StatusFailed:
		return true
	default:
		return false
	}
}

func ValidateTransition(from Status, to Status) error {
	from = NormalizeStatus(string(from))
	to = NormalizeStatus(string(to))

	if !ValidateStatus(from) {
		return fmt.Errorf("job status %q is invalid", from)
	}

	if !ValidateStatus(to) {
		return fmt.Errorf("job status %q is invalid", to)
	}

	switch from {
	case StatusQueued:
		if to == StatusRunning {
			return nil
		}
	case StatusRunning:
		if to == StatusSuccess || to == StatusFailed {
			return nil
		}
	}

	return fmt.Errorf("job transition %q -> %q is invalid: %w", from, to, ErrInvalidTransition)
}
