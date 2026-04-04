package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/observations"
	protocolwinrm "github.com/mbaybarsk/openbadger/internal/protocols/winrm"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

type winrmRunner struct {
	collector protocolwinrm.Collector
	expander  targets.Expander
	now       func() time.Time
}

func newWinRMRunner(collector protocolwinrm.Collector, now func() time.Time) Runner {
	if collector == nil {
		collector = protocolwinrm.NewCollector()
	}

	if now == nil {
		now = time.Now
	}

	return winrmRunner{
		collector: collector,
		expander:  targets.Expander{MaxTargets: targets.DefaultMaxExpandedTargets},
		now:       now,
	}
}

func (r winrmRunner) Capability() string {
	return "winrm"
}

func (r winrmRunner) Run(ctx context.Context, request RunRequest) ([]observations.Observation, error) {
	if err := validateRunRequest(request); err != nil {
		return nil, err
	}

	payload, err := jobtypes.ParseWinRMScanPayload(request.Job.Payload)
	if err != nil {
		return nil, err
	}

	expanded, err := r.expander.Expand(payload.TargetRanges())
	if err != nil {
		return nil, fmt.Errorf("expand winrm targets: %w", err)
	}

	results := make([]observations.Observation, 0)
	for _, target := range expanded {
		scanResult, err := r.collector.Collect(ctx, protocolwinrm.Request{
			Target:     target.IP,
			Port:       payload.EffectivePort(),
			Timeout:    payload.Timeout(),
			Credential: payload.Credential(),
		})
		if err != nil {
			if errors.Is(err, protocolwinrm.ErrNoResponse) {
				continue
			}

			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			return nil, fmt.Errorf("collect winrm target %q: %w", target.IP, err)
		}

		observedAt := r.now().UTC()
		normalized, err := protocolwinrm.NormalizeObservations(protocolwinrm.NormalizeContext{
			SiteID:            request.Node.SiteID,
			JobID:             strings.TrimSpace(request.Job.ID),
			NodeKind:          string(request.Node.Kind),
			NodeID:            request.Node.NodeID,
			NodeName:          request.Node.Name,
			Version:           request.Version,
			TargetInput:       target.Input,
			TargetIP:          target.IP,
			Port:              payload.EffectivePort(),
			ObservedAt:        observedAt,
			CredentialProfile: payload.CredentialReference(),
		}, scanResult)
		if err != nil {
			return nil, fmt.Errorf("normalize winrm observations for %q: %w", target.IP, err)
		}

		results = append(results, normalized...)
	}

	return results, nil
}
