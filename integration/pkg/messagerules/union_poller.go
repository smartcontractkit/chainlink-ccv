package messagerules

import (
	"context"
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

var _ common.MessageRulesCheckerService = (*UnionPollerService)(nil)

// NamedPoller pairs a per-aggregator poller with its label for health reporting.
type NamedPoller struct {
	label  string
	poller common.MessageRulesCheckerService
}

// UnionPollerService aggregates message-disablement rules across multiple aggregators with
// fail-safe union semantics:
//
//   - A message is disabled if ANY aggregator's rules disable it (so no kill-switch set on any
//     aggregator is silently ignored). Disabled takes precedence over unknown: a known
//     disablement results in (true, nil) so the task is dropped rather than retried.
//   - If no aggregator disables the message but ANY aggregator is in the unknown state (no
//     successful poll yet), the result is (true, ErrMessageRulesStateUnknown) so verification is
//     blocked and retried (strict fail-safe). One unreachable rules endpoint therefore blocks the
//     whole consolidated job.
type UnionPollerService struct {
	services.StateMachine
	pollers []NamedPoller
	lggr    logger.Logger
}

// NewUnionPollerService builds a union poller over the given per-aggregator pollers. At least one
// poller is required.
func NewUnionPollerService(lggr logger.Logger, pollers ...NamedPoller) (*UnionPollerService, error) {
	if len(pollers) == 0 {
		return nil, fmt.Errorf("union poller requires at least one aggregator poller")
	}
	return &UnionPollerService{pollers: pollers, lggr: lggr}, nil
}

// NewNamedPoller pairs a poller with an aggregator label for use with NewUnionPollerService.
func NewNamedPoller(label string, poller common.MessageRulesCheckerService) NamedPoller {
	return NamedPoller{label: label, poller: poller}
}

func (u *UnionPollerService) Start(ctx context.Context) error {
	return u.StartOnce(u.Name(), func() error {
		started := make([]NamedPoller, 0, len(u.pollers))
		for _, p := range u.pollers {
			if err := p.poller.Start(ctx); err != nil {
				// Roll back any pollers already started before failing.
				for _, s := range started {
					_ = s.poller.Close()
				}
				return fmt.Errorf("failed to start message rules poller for %q: %w", p.label, err)
			}
			started = append(started, p)
		}
		u.lggr.Infow("Union message rules service started", "aggregatorCount", len(u.pollers))
		return nil
	})
}

func (u *UnionPollerService) Close() error {
	return u.StopOnce(u.Name(), func() error {
		var errs []error
		for _, p := range u.pollers {
			if err := p.poller.Close(); err != nil {
				errs = append(errs, fmt.Errorf("aggregator %q: %w", p.label, err))
			}
		}
		return errors.Join(errs...)
	})
}

// IsMessageDisabled applies fail-safe union semantics across all aggregator pollers.
func (u *UnionPollerService) IsMessageDisabled(ctx context.Context, message protocol.Message) (bool, error) {
	anyUnknown := false
	for _, p := range u.pollers {
		disabled, err := p.poller.IsMessageDisabled(ctx, message)
		if err != nil {
			// Unknown state (or any other error) blocks fail-safe, unless another source has a
			// definitive disablement (handled by the disabled check below across all sources).
			anyUnknown = true
			continue
		}
		if disabled {
			return true, nil
		}
	}
	if anyUnknown {
		return true, common.ErrMessageRulesStateUnknown
	}
	return false, nil
}

func (u *UnionPollerService) HealthReport() map[string]error {
	report := map[string]error{u.Name(): u.Ready()}
	for _, p := range u.pollers {
		for k, v := range p.poller.HealthReport() {
			report[fmt.Sprintf("%s[%s]", k, p.label)] = v
		}
	}
	return report
}

func (u *UnionPollerService) Name() string {
	return "messagerules.UnionPollerService"
}
