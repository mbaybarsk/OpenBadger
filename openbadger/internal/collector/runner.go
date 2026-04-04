package collector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/observations"
)

type Runner interface {
	Capability() string
	Run(ctx context.Context, request RunRequest) ([]observations.Observation, error)
}

type RunRequest struct {
	Job     jobtypes.Record
	Node    nodes.State
	Version string
}

type runnerRegistry struct {
	byCapability map[string]Runner
}

func newRunnerRegistry(runners ...Runner) runnerRegistry {
	registry := runnerRegistry{byCapability: make(map[string]Runner, len(runners))}
	for _, runner := range runners {
		if runner == nil {
			continue
		}

		registry.byCapability[strings.ToLower(strings.TrimSpace(runner.Capability()))] = runner
	}

	return registry
}

func (r runnerRegistry) Select(job jobtypes.Record) Runner {
	if strings.EqualFold(strings.TrimSpace(job.Kind), "demo") {
		return r.byCapability["demo"]
	}

	return r.byCapability[strings.ToLower(strings.TrimSpace(job.Capability))]
}

type demoRunner struct {
	now func() time.Time
}

func newDemoRunner(now func() time.Time) Runner {
	if now == nil {
		now = time.Now
	}

	return demoRunner{now: now}
}

func (r demoRunner) Capability() string {
	return "demo"
}

func (r demoRunner) Run(_ context.Context, request RunRequest) ([]observations.Observation, error) {
	if err := validateRunRequest(request); err != nil {
		return nil, err
	}

	protocol := strings.ToLower(strings.TrimSpace(request.Job.Capability))
	if protocol == "" {
		protocol = "icmp"
	}

	observedAt := r.now().UTC().Truncate(time.Second)
	observation := observations.Observation{
		SchemaVersion: observations.SchemaVersion,
		ObservationID: uuid.NewString(),
		Type:          "icmp.alive",
		Scope:         "sighting",
		SiteID:        request.Node.SiteID,
		JobID:         strings.TrimSpace(request.Job.ID),
		Emitter: &observations.Emitter{
			Kind:       string(request.Node.Kind),
			ID:         request.Node.NodeID,
			Name:       request.Node.Name,
			Version:    strings.TrimSpace(request.Version),
			Capability: protocol,
		},
		ObservedAt: observedAt,
		Target: &observations.Target{
			Input:    "demo-host-01",
			IP:       "192.0.2.10",
			Protocol: protocol,
		},
		Addresses: &observations.Addresses{
			IPAddresses: []string{"192.0.2.10"},
		},
		Facts: map[string]any{
			"rtt_ms":    1.25,
			"ttl":       64,
			"synthetic": true,
		},
		Evidence: &observations.Evidence{
			Confidence:     0.9,
			SourceProtocol: protocol,
			FirstSeen:      timeRef(observedAt),
			LastSeen:       timeRef(observedAt),
		},
		Raw: map[string]any{
			"generator": "demo_runner",
		},
	}

	return []observations.Observation{observation}, nil
}

func validateRunRequest(request RunRequest) error {
	if strings.TrimSpace(request.Node.NodeID) == "" {
		return fmt.Errorf("runner node id is required")
	}

	if strings.TrimSpace(request.Node.SiteID) == "" {
		return fmt.Errorf("runner site id is required")
	}

	return nil
}

func timeRef(value time.Time) *time.Time {
	copy := value
	return &copy
}
