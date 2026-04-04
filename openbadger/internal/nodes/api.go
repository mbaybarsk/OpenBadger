package nodes

import "time"

type EnrollRequest struct {
	SiteID       string   `json:"site_id"`
	Kind         Kind     `json:"kind"`
	Name         string   `json:"name"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type EnrollResponse struct {
	NodeID    string `json:"node_id"`
	SiteID    string `json:"site_id"`
	Kind      Kind   `json:"kind"`
	Name      string `json:"name"`
	AuthToken string `json:"auth_token"`
}

type HeartbeatRequest struct {
	Name         string   `json:"name"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	HealthStatus string   `json:"health_status,omitempty"`
}

type HeartbeatResponse struct {
	NodeID          string    `json:"node_id"`
	SiteID          string    `json:"site_id"`
	Kind            Kind      `json:"kind"`
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Capabilities    []string  `json:"capabilities"`
	HealthStatus    string    `json:"health_status"`
	LastHeartbeatAt time.Time `json:"last_heartbeat_at"`
}

type DebugRecord struct {
	NodeID          string     `json:"node_id"`
	SiteID          string     `json:"site_id"`
	Kind            Kind       `json:"kind"`
	Name            string     `json:"name"`
	Version         string     `json:"version"`
	Capabilities    []string   `json:"capabilities"`
	HealthStatus    string     `json:"health_status"`
	Stale           bool       `json:"stale"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
