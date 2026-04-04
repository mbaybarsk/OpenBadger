package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/observations"
	protocolsnmp "github.com/mbaybarsk/openbadger/internal/protocols/snmp"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

type snmpRunner struct {
	collector protocolsnmp.Collector
	expander  targets.Expander
	now       func() time.Time
}

func newSNMPRunner(collector protocolsnmp.Collector, now func() time.Time) Runner {
	if collector == nil {
		collector = protocolsnmp.NewCollector(nil)
	}

	if now == nil {
		now = time.Now
	}

	return snmpRunner{
		collector: collector,
		expander:  targets.Expander{MaxTargets: targets.DefaultMaxExpandedTargets},
		now:       now,
	}
}

func (r snmpRunner) Capability() string {
	return "snmp"
}

func (r snmpRunner) Run(ctx context.Context, request RunRequest) ([]observations.Observation, error) {
	if err := validateRunRequest(request); err != nil {
		return nil, err
	}

	payload, err := jobtypes.ParseSNMPScanPayload(request.Job.Payload)
	if err != nil {
		return nil, err
	}

	expanded, err := r.expander.Expand(payload.TargetRanges())
	if err != nil {
		return nil, fmt.Errorf("expand snmp targets: %w", err)
	}

	results := make([]observations.Observation, 0)
	for _, target := range expanded {
		scanResult, err := r.collector.Collect(ctx, protocolsnmp.Request{
			Target:     target.IP,
			Port:       payload.EffectivePort(),
			Timeout:    payload.Timeout(),
			Retries:    payload.RetryCount,
			Credential: payload.Credential(),
		})
		if err != nil {
			if errors.Is(err, protocolsnmp.ErrNoResponse) {
				continue
			}

			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			return nil, fmt.Errorf("collect snmp target %q: %w", target.IP, err)
		}

		observedAt := r.now().UTC()
		normalized, err := protocolsnmp.NormalizeObservations(protocolsnmp.NormalizeContext{
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
			return nil, fmt.Errorf("normalize snmp observations for %q: %w", target.IP, err)
		}

		results = append(results, normalized...)
	}

	return results, nil
}
