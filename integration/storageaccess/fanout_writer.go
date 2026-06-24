package storageaccess

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.CCVNodeDataWriter = (*FanOutWriter)(nil)

// AggregatorTarget describes one aggregator the fan-out writer delivers to.
type AggregatorTarget struct {
	// Label identifies the aggregator in logs and metrics.
	Label string
	// Address is the aggregator gRPC endpoint.
	Address string
	// Insecure disables TLS for this aggregator's connection.
	Insecure bool
	// HMACConfig holds this aggregator's HMAC credentials. Each aggregator authenticates the
	// verifier with its own credential, so this is per-target rather than shared.
	HMACConfig *hmac.ClientConfig
	// MaxSendMsgSizeBytes / MaxRecvMsgSizeBytes set per-aggregator gRPC message-size limits
	// (0 -> DefaultMaxMessageSize).
	MaxSendMsgSizeBytes int
	MaxRecvMsgSizeBytes int
}

// namedWriter pairs a per-aggregator writer with its label for result merging and logging.
type namedWriter struct {
	label  string
	writer protocol.CCVNodeDataWriter
}

// FanOutWriter writes each VerifierNodeResult to all configured aggregators concurrently and
// merges the per-item outcomes. Aggregators are independent sinks, so an item is only reported
// as written (WriteSuccess) when every aggregator acks it. Because aggregator writes are
// idempotent, retried re-sends to aggregators that already have the item are safe no-ops.
//
// Each aggregator has its own resilience (circuit breaker etc.) and observed wrapper, so a slow
// or failing aggregator does not impede writes to the healthy ones.
type FanOutWriter struct {
	writers []namedWriter
	closers []*AggregatorWriter
	lggr    logger.Logger
}

// NewFanOutAggregatorWriter builds a fan-out writer over the given aggregator targets. For each
// target it constructs an AggregatorWriter, wraps it in the default resilience policies, and
// then in a per-aggregator observed writer (so metrics carry an "aggregator" label). At least
// one target is required.
func NewFanOutAggregatorWriter(
	targets []AggregatorTarget,
	verifierID string,
	lggr logger.Logger,
	monitoring verifier.Monitoring,
) (*FanOutWriter, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("fan-out writer requires at least one aggregator target")
	}

	f := &FanOutWriter{
		writers: make([]namedWriter, 0, len(targets)),
		closers: make([]*AggregatorWriter, 0, len(targets)),
		lggr:    lggr,
	}

	for _, t := range targets {
		aggWriter, err := NewAggregatorWriter(
			t.Address,
			logger.With(lggr, "aggregator", t.Label),
			t.HMACConfig,
			t.Insecure,
			t.MaxSendMsgSizeBytes,
			t.MaxRecvMsgSizeBytes,
		)
		if err != nil {
			// Best-effort close anything created so far before returning.
			_ = f.Close()
			return nil, fmt.Errorf("failed to create aggregator writer for %q: %w", t.Label, err)
		}

		observed, err := NewObservedAggregatorWriter(
			NewDefaultResilientStorageWriter(aggWriter, logger.With(lggr, "aggregator", t.Label)),
			verifierID,
			t.Label,
			lggr,
			monitoring,
		)
		if err != nil {
			// Best-effort close anything created so far before returning.
			_ = f.Close()
			return nil, fmt.Errorf("failed to create observed aggregator writer for %q: %w", t.Label, err)
		}

		f.writers = append(f.writers, namedWriter{label: t.Label, writer: observed})
		f.closers = append(f.closers, aggWriter)
	}

	return f, nil
}

// WriteCCVNodeData writes every item to all aggregators concurrently and merges the results.
// The returned slice has the same length and ordering as ccvDataList.
func (f *FanOutWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	if len(ccvDataList) == 0 {
		return nil, nil
	}

	perAggregator := make([][]protocol.WriteResult, len(f.writers))
	var wg sync.WaitGroup
	for i := range f.writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			perAggregator[i] = f.writeToAggregator(ctx, f.writers[i], ccvDataList)
		}(i)
	}
	// wg.Wait() is bounded even when ctx has no deadline (the caller passes the long-lived
	// service context). Each writer built by NewFanOutAggregatorWriter is wrapped in the
	// resilient writer, whose innermost failsafe timeout policy (WriteTimeout, default 2s)
	// cancels the per-attempt context and aborts the underlying gRPC call. A stalled aggregator
	// therefore returns within ~WriteTimeout rather than blocking the fan-out forever. This
	// invariant relies on the resilient wrapper being present, which the constructor guarantees.
	wg.Wait()

	return f.merge(ccvDataList, perAggregator), nil
}

// writeToAggregator writes to a single aggregator and always returns a result slice aligned to
// ccvDataList, synthesizing retryable failures if the writer returns a short or nil slice.
func (f *FanOutWriter) writeToAggregator(ctx context.Context, nw namedWriter, ccvDataList []protocol.VerifierNodeResult) []protocol.WriteResult {
	results, err := nw.writer.WriteCCVNodeData(ctx, ccvDataList)
	if len(results) == len(ccvDataList) {
		return results
	}

	// The writer returned an incomplete result set (e.g. a failsafe policy short-circuited with
	// no per-item results). Treat every item as a retryable failure for this aggregator.
	if err == nil {
		err = fmt.Errorf("aggregator %q returned %d results for %d items", nw.label, len(results), len(ccvDataList))
	}
	synthesized := make([]protocol.WriteResult, len(ccvDataList))
	for i, data := range ccvDataList {
		if i < len(results) {
			synthesized[i] = results[i]
			continue
		}
		synthesized[i] = protocol.WriteResult{
			Input:     data,
			Status:    protocol.WriteFailure,
			Error:     err,
			Retryable: true,
		}
	}
	return synthesized
}

// merge collapses the per-aggregator results into one result per item using all-must-ack
// semantics:
//   - success only when every aggregator acked the item;
//   - on failure, retryable unless any aggregator returned a non-retryable error (retrying
//     cannot help that aggregator, so the item is failed permanently and logged distinctly).
func (f *FanOutWriter) merge(ccvDataList []protocol.VerifierNodeResult, perAggregator [][]protocol.WriteResult) []protocol.WriteResult {
	merged := make([]protocol.WriteResult, len(ccvDataList))
	for i, data := range ccvDataList {
		var (
			anyFailure      bool
			anyNonRetryable bool
			errs            []error
			failedLabels    []string
		)
		for a := range f.writers {
			r := perAggregator[a][i]
			if r.Status == protocol.WriteSuccess {
				continue
			}
			anyFailure = true
			failedLabels = append(failedLabels, f.writers[a].label)
			if !r.Retryable {
				anyNonRetryable = true
			}
			if r.Error != nil {
				errs = append(errs, fmt.Errorf("aggregator %q: %w", f.writers[a].label, r.Error))
			}
		}

		if !anyFailure {
			merged[i] = protocol.WriteResult{Input: data, Status: protocol.WriteSuccess}
			continue
		}

		merged[i] = protocol.WriteResult{
			Input:     data,
			Status:    protocol.WriteFailure,
			Error:     errors.Join(errs...),
			Retryable: !anyNonRetryable,
		}

		if anyNonRetryable {
			// Permanent partial write: some aggregators may have the item, but at least one
			// rejected it non-retryably and re-sending will not help. The item will not be
			// retried, so those aggregators will not receive it.
			f.lggr.Errorw("Permanent partial write: item rejected non-retryably by an aggregator and will not be retried",
				"messageID", data.MessageID.String(),
				"sourceChain", data.Message.SourceChainSelector,
				"failedAggregators", failedLabels,
				"error", merged[i].Error,
			)
		}
	}
	return merged
}

// GetStats aggregates per-aggregator stats keyed by aggregator label.
func (f *FanOutWriter) GetStats() map[string]any {
	stats := make(map[string]any, len(f.closers))
	for i, w := range f.closers {
		stats[f.writers[i].label] = w.GetStats()
	}
	return stats
}

// Close closes every aggregator's gRPC connection, returning the joined error.
func (f *FanOutWriter) Close() error {
	var errs []error
	for _, w := range f.closers {
		if err := w.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
