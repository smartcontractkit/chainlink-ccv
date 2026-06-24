package heartbeatclient

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ HeartbeatSender = (*FanOutHeartbeatSender)(nil)

// AggregatorTarget describes one aggregator the fan-out heartbeat sender delivers to.
type AggregatorTarget struct {
	// Label identifies the aggregator in logs and metrics.
	Label string
	// Address is the aggregator gRPC endpoint.
	Address string
	// Insecure disables TLS for this aggregator's connection.
	Insecure bool
	// HMACConfig holds this aggregator's HMAC credentials (per-aggregator, not shared).
	HMACConfig *hmac.ClientConfig
}

type labeledSender struct {
	label  string
	sender HeartbeatSender
}

// FanOutHeartbeatSender sends each heartbeat to all configured aggregators. Per-aggregator
// outcomes (sent/failed counters, durations) are recorded by each wrapped observed client under
// an "aggregator" metric label. A failure to one aggregator is logged and does not prevent the
// others from receiving the heartbeat: SendHeartbeat returns an error only when every aggregator
// fails.
type FanOutHeartbeatSender struct {
	senders []labeledSender
	lggr    logger.Logger
}

// NewFanOutHeartbeatSender builds a fan-out heartbeat sender over the given aggregator targets.
// Each target gets its own heartbeat client wrapped in an observed client labeled with the
// aggregator, so per-aggregator liveness metrics are emitted. At least one target is required.
func NewFanOutHeartbeatSender(
	targets []AggregatorTarget,
	verifierID string,
	lggr logger.Logger,
	monitoring Monitoring,
) (*FanOutHeartbeatSender, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("fan-out heartbeat sender requires at least one aggregator target")
	}

	f := &FanOutHeartbeatSender{
		senders: make([]labeledSender, 0, len(targets)),
		lggr:    lggr,
	}

	for _, t := range targets {
		aggLggr := logger.With(lggr, "aggregator", t.Label)
		client, err := NewHeartbeatClient(t.Address, aggLggr, t.HMACConfig, t.Insecure)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to create heartbeat client for %q: %w", t.Label, err)
		}

		observed := NewObservedHeartbeatClient(
			client,
			verifierID,
			aggLggr,
			aggregatorLabeledMonitoring{inner: monitoring, label: t.Label},
		)
		f.senders = append(f.senders, labeledSender{label: t.Label, sender: observed})
	}

	return f, nil
}

// SendHeartbeat sends the heartbeat to all aggregators concurrently. It returns the first
// successful response, or a joined error if all aggregators failed.
func (f *FanOutHeartbeatSender) SendHeartbeat(ctx context.Context, blockHeightsByChain map[uint64]uint64) (HeartbeatResponse, error) {
	type outcome struct {
		resp HeartbeatResponse
		err  error
	}
	outcomes := make([]outcome, len(f.senders))

	var wg sync.WaitGroup
	for i := range f.senders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := f.senders[i].sender.SendHeartbeat(ctx, blockHeightsByChain)
			outcomes[i] = outcome{resp: resp, err: err}
		}(i)
	}
	wg.Wait()

	var (
		errs        []error
		firstOK     *HeartbeatResponse
		failedCount int
	)
	for i, o := range outcomes {
		if o.err != nil {
			failedCount++
			errs = append(errs, fmt.Errorf("aggregator %q: %w", f.senders[i].label, o.err))
			continue
		}
		if firstOK == nil {
			resp := o.resp
			firstOK = &resp
		}
	}

	if firstOK == nil {
		return HeartbeatResponse{}, fmt.Errorf("all aggregators failed to receive heartbeat: %w", errors.Join(errs...))
	}
	if failedCount > 0 {
		f.lggr.Warnw("Heartbeat failed for some aggregators",
			"failedCount", failedCount,
			"totalAggregators", len(f.senders),
			"error", errors.Join(errs...),
		)
	}
	return *firstOK, nil
}

// Close closes every aggregator's heartbeat client, returning the joined error.
func (f *FanOutHeartbeatSender) Close() error {
	var errs []error
	for _, s := range f.senders {
		if err := s.sender.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// aggregatorLabeledMonitoring decorates a Monitoring so that every MetricLabeler it hands out is
// pre-tagged with the aggregator label.
type aggregatorLabeledMonitoring struct {
	inner Monitoring
	label string
}

func (m aggregatorLabeledMonitoring) Metrics() MetricLabeler {
	return m.inner.Metrics().With("aggregator_name", m.label)
}
