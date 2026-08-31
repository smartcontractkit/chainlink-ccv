package messagerules

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

var _ common.MessageRulesCheckerService = (*MultiAggregatorRulesChecker)(nil)

// NamedPoller pairs a per-aggregator poller with its label for health reporting.
type NamedPoller struct {
	label  string
	poller common.MessageRulesCheckerService
}

// MultiAggregatorRulesChecker aggregates message-disablement rules across multiple aggregators,
// relying on the assumption that all aggregators hold the same rules:
//
//   - A message is disabled if ANY reachable aggregator's rules disable it. Disabled takes
//     precedence over unknown: a known disablement from a single source results in (true, nil)
//     so the task is dropped rather than retried.
//   - Sources whose rules are unknown (unreachable, or no successful poll yet) are skipped: we
//     rely on any aggregator that has reported rules rather than blocking the whole job. This
//     means a verifier starting or restarting while an aggregator is down still attests messages,
//     using the rules of the aggregators it can reach.
//   - Only when NO aggregator is reachable / has reported rules does the checker fail closed,
//     returning (true, ErrMessageRulesStateUnknown) so verification is blocked and retried.
type MultiAggregatorRulesChecker struct {
	services.StateMachine
	pollers []NamedPoller
	metrics common.MessageRulesCheckerMetrics
	lggr    logger.Logger
}

// NewMultiAggregatorRulesChecker builds a checker over the given per-aggregator pollers. At least
// one poller is required.
func NewMultiAggregatorRulesChecker(lggr logger.Logger, metrics common.MessageRulesCheckerMetrics, pollers ...NamedPoller) (*MultiAggregatorRulesChecker, error) {
	if len(pollers) == 0 {
		return nil, fmt.Errorf("multi-aggregator rules checker requires at least one aggregator poller")
	}
	return &MultiAggregatorRulesChecker{pollers: pollers, metrics: metrics, lggr: lggr}, nil
}

// NewNamedPoller pairs a poller with an aggregator label for use with
// NewMultiAggregatorRulesChecker.
func NewNamedPoller(label string, poller common.MessageRulesCheckerService) NamedPoller {
	return NamedPoller{label: label, poller: poller}
}

func (m *MultiAggregatorRulesChecker) Start(ctx context.Context) error {
	return m.StartOnce(m.Name(), func() error {
		started := make([]NamedPoller, 0, len(m.pollers))
		for _, p := range m.pollers {
			if err := p.poller.Start(ctx); err != nil {
				// Roll back any pollers already started before failing.
				for _, s := range started {
					_ = s.poller.Close()
				}
				return fmt.Errorf("failed to start message rules poller for %q: %w", p.label, err)
			}
			started = append(started, p)
		}
		m.lggr.Infow("Multi-aggregator message rules service started", "aggregatorCount", len(m.pollers))
		return nil
	})
}

func (m *MultiAggregatorRulesChecker) Close() error {
	return m.StopOnce(m.Name(), func() error {
		var errs []error
		for _, p := range m.pollers {
			if err := p.poller.Close(); err != nil {
				errs = append(errs, fmt.Errorf("aggregator %q: %w", p.label, err))
			}
		}
		return errors.Join(errs...)
	})
}

// IsMessageDisabled checks across all aggregator pollers under the identical-rules assumption.
// All sources are consulted concurrently. Sources with unknown rules are skipped in favor of any
// source that has reported rules; the checker fails closed (ErrMessageRulesStateUnknown) only when
// no source has rules.
//
// Reachable sources that DISAGREE on the message — the identical-rules assumption violated — are
// surfaced (logged and metered) and resolved toward the more restrictive outcome: a message is
// disabled if any reachable source disables it.
func (m *MultiAggregatorRulesChecker) IsMessageDisabled(ctx context.Context, message protocol.Message) (bool, error) {
	type sourceResult struct {
		index    int
		disabled bool
		err      error
	}

	results := make([]sourceResult, len(m.pollers))
	var wg sync.WaitGroup
	for i, p := range m.pollers {
		wg.Add(1)
		go func(i int, p NamedPoller) {
			defer wg.Done()
			results[i].index = i
			results[i].disabled, results[i].err = p.poller.IsMessageDisabled(ctx, message)
		}(i, p)
	}
	wg.Wait()

	var (
		anySuccessful  bool
		anyDisabled    bool
		anyEnabled     bool
		disabledLabels []string
		enabledLabels  []string
	)
	for _, r := range results {
		if r.err != nil {
			// Unknown state (or any other error): this aggregator is unreachable or has not
			// successfully polled yet. Assume all aggregators hold identical rules, so skip it
			// and rely on any source that has reported rules.
			continue
		}
		anySuccessful = true
		label := m.pollers[r.index].label
		if r.disabled {
			anyDisabled = true
			disabledLabels = append(disabledLabels, label)
		} else {
			anyEnabled = true
			enabledLabels = append(enabledLabels, label)
		}
	}
	if !anySuccessful {
		return true, common.ErrMessageRulesStateUnknown
	}
	if anyDisabled && anyEnabled {
		if m.metrics != nil {
			m.metrics.RecordMessageDisablementRulesMismatch(ctx)
		}
		m.lggr.Warnw("Aggregators disagree on message disablement; assuming disabled (more restrictive)",
			protocol.LogKeyMessageID, message.MustMessageID().String(),
			protocol.LogKeySourceChain, message.SourceChainSelector,
			protocol.LogKeyDestChain, message.DestChainSelector,
			"disabledAggregators", disabledLabels,
			"enabledAggregators", enabledLabels)
	}
	return anyDisabled, nil
}

func (m *MultiAggregatorRulesChecker) HealthReport() map[string]error {
	report := map[string]error{m.Name(): m.Ready()}
	for _, p := range m.pollers {
		for k, v := range p.poller.HealthReport() {
			report[fmt.Sprintf("%s[%s]", k, p.label)] = v
		}
	}
	return report
}

func (m *MultiAggregatorRulesChecker) Name() string {
	return "messagerules.MultiAggregatorRulesChecker"
}
