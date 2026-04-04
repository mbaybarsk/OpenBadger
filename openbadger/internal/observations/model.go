package observations

import (
	"fmt"
	"strings"
	"time"
)

const SchemaVersion = "0.1"

type BatchRequest struct {
	Observations []Observation `json:"observations"`
}

type BatchResponse struct {
	Accepted int `json:"accepted"`
}

type Observation struct {
	SchemaVersion string           `json:"schema_version"`
	ObservationID string           `json:"observation_id"`
	Type          string           `json:"type"`
	Scope         string           `json:"scope"`
	SiteID        string           `json:"site_id"`
	JobID         string           `json:"job_id,omitempty"`
	Emitter       *Emitter         `json:"emitter"`
	ObservedAt    time.Time        `json:"observed_at"`
	Target        *Target          `json:"target,omitempty"`
	Identifiers   *Identifiers     `json:"identifiers,omitempty"`
	Addresses     *Addresses       `json:"addresses,omitempty"`
	Facts         map[string]any   `json:"facts"`
	Relations     []map[string]any `json:"relations,omitempty"`
	Evidence      *Evidence        `json:"evidence"`
	Raw           map[string]any   `json:"raw,omitempty"`
}

type Emitter struct {
	Kind       string `json:"kind,omitempty"`
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Capability string `json:"capability,omitempty"`
}

type Target struct {
	Input    string `json:"input,omitempty"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type Identifiers struct {
	Hostnames              []string `json:"hostnames,omitempty"`
	FQDN                   string   `json:"fqdn,omitempty"`
	MACAddresses           []string `json:"mac_addresses,omitempty"`
	SerialNumber           string   `json:"serial_number,omitempty"`
	SystemUUID             string   `json:"system_uuid,omitempty"`
	BIOSUUID               string   `json:"bios_uuid,omitempty"`
	SNMPEngineID           string   `json:"snmp_engine_id,omitempty"`
	SSHHostKeyFingerprints []string `json:"ssh_host_key_fingerprints,omitempty"`
	MachineID              string   `json:"machine_id,omitempty"`
}

type Addresses struct {
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	VLANIDs        []int    `json:"vlan_ids,omitempty"`
	SubnetCIDRs    []string `json:"subnet_cidrs,omitempty"`
	InterfaceName  string   `json:"interface_name,omitempty"`
	InterfaceIndex int      `json:"interface_index,omitempty"`
}

type Evidence struct {
	Confidence        float64    `json:"confidence,omitempty"`
	SourceProtocol    string     `json:"source_protocol,omitempty"`
	CredentialProfile string     `json:"credential_profile,omitempty"`
	FirstSeen         *time.Time `json:"first_seen,omitempty"`
	LastSeen          *time.Time `json:"last_seen,omitempty"`
	PacketCount       int64      `json:"packet_count,omitempty"`
	ByteCount         int64      `json:"byte_count,omitempty"`
	FlowCount         int64      `json:"flow_count,omitempty"`
}

func (r BatchRequest) Validate() error {
	if len(r.Observations) == 0 {
		return fmt.Errorf("observations are required")
	}

	for i, observation := range r.Observations {
		if err := observation.Validate(); err != nil {
			return fmt.Errorf("observations[%d]: %w", i, err)
		}
	}

	return nil
}

func (o Observation) Validate() error {
	if strings.TrimSpace(o.SchemaVersion) != SchemaVersion {
		return fmt.Errorf("observation schema_version is invalid")
	}

	if strings.TrimSpace(o.ObservationID) == "" {
		return fmt.Errorf("observation observation_id is required")
	}

	if strings.TrimSpace(o.Type) == "" {
		return fmt.Errorf("observation type is required")
	}

	if !validScope(o.Scope) {
		return fmt.Errorf("observation scope is invalid")
	}

	if strings.TrimSpace(o.SiteID) == "" {
		return fmt.Errorf("observation site_id is required")
	}

	if o.Emitter == nil {
		return fmt.Errorf("observation emitter is required")
	}

	if o.ObservedAt.IsZero() {
		return fmt.Errorf("observation observed_at is required")
	}

	if o.Facts == nil {
		return fmt.Errorf("observation facts is required")
	}

	if o.Evidence == nil {
		return fmt.Errorf("observation evidence is required")
	}

	return nil
}

func validScope(scope string) bool {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "asset", "sighting", "relationship":
		return true
	default:
		return false
	}
}
