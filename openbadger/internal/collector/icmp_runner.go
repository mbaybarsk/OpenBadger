package collector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/observations"
	protocolicmp "github.com/mbaybarsk/openbadger/internal/protocols/icmp"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

type icmpRunner struct {
	prober   protocolicmp.Prober
	expander targets.Expander
	now      func() time.Time
}

func newICMPRunner(prober protocolicmp.Prober, now func() time.Time) Runner {
	if prober == nil {
		prober = protocolicmp.NewRawProber()
	}

	if now == nil {
		now = time.Now
	}

	return icmpRunner{
		prober:   prober,
		expander: targets.Expander{MaxTargets: targets.DefaultMaxExpandedTargets},
		now:      now,
	}
}

func (r icmpRunner) Capability() string {
	return "icmp"
}

func (r icmpRunner) Run(ctx context.Context, request RunRequest) ([]observations.Observation, error) {
	if err := validateRunRequest(request); err != nil {
		return nil, err
	}

	payload, err := jobtypes.ParseICMPScanPayload(request.Job.Payload)
	if err != nil {
		return nil, err
	}

	expanded, err := r.expander.Expand(payload.TargetRanges())
	if err != nil {
		return nil, fmt.Errorf("expand icmp targets: %w", err)
	}

	results := make([]observations.Observation, 0, len(expanded))
	timeout := payload.Timeout()
	for _, target := range expanded {
		ip, err := netip.ParseAddr(target.IP)
		if err != nil {
			return nil, fmt.Errorf("parse expanded target %q: %w", target.IP, err)
		}

		probe, err := r.prober.Probe(ctx, ip, timeout)
		if err != nil {
			if errors.Is(err, protocolicmp.ErrNoReply) {
				continue
			}

			return nil, fmt.Errorf("probe target %q: %w", target.IP, err)
		}

		observedAt := probe.ObservedAt
		if observedAt.IsZero() {
			observedAt = r.now().UTC()
		}

		observation, err := protocolicmp.NormalizeAliveObservation(protocolicmp.NormalizeRequest{
			SiteID:      request.Node.SiteID,
			JobID:       strings.TrimSpace(request.Job.ID),
			NodeKind:    string(request.Node.Kind),
			NodeID:      request.Node.NodeID,
			NodeName:    request.Node.Name,
			Version:     request.Version,
			TargetInput: target.Input,
			IP:          probe.IP,
			ObservedAt:  observedAt,
			RTT:         probe.RTT,
			TTL:         probe.TTL,
		})
		if err != nil {
			return nil, fmt.Errorf("normalize icmp observation for %q: %w", target.IP, err)
		}

		results = append(results, observation)
	}

	return results, nil
}
