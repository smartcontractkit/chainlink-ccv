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
//
// To avoid re-fanning a retry out to aggregators that already confirmed the write, acks are
// tracked per (aggregator, message) in process memory. Once an aggregator acks a message it is
// skipped on every later attempt, so a single down aggregator no longer makes the healthy ones
// receive the same item on every retry. The tracking is best-effort and volatile: after a
// restart every aggregator receives each message once more, then the acks are re-learned.
type FanOutWriter struct {
	writers []namedWriter
	closers []*AggregatorWriter
	lggr    logger.Logger

	mu sync.Mutex
	// acked records, per aggregator label, the set of message IDs that aggregator has
	// already confirmed. Guarded by mu.
	acked map[string]map[string]struct{}
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
		acked:   make(map[string]map[string]struct{}, len(targets)),
		lggr:    lggr,
	}

	for _, t := range targets {
		aggWriter, err := NewAggregatorWriter(
			t.Address,
			logger.With(lggr, "target", t.Label),
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
			NewDefaultResilientOffchainWriter(aggWriter, logger.With(lggr, "target", t.Label)),
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
		f.acked[t.Label] = make(map[string]struct{})
	}

	return f, nil
}

// WriteCCVNodeData writes each item to every aggregator that has not yet confirmed it, and
// merges the results. An item already confirmed by an aggregator is skipped for that
// aggregator, so a retry triggered by one failing aggregator does not re-send the item to the
// healthy ones. The returned slice has the same length and ordering as ccvDataList.
func (f *FanOutWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	if len(ccvDataList) == 0 {
		return nil, nil
	}

	// Per-aggregator plan: which items still need writing, and where each maps back into the
	// caller's slice. Items an aggregator already acked are left out and never re-sent.
	outstanding := make([][]protocol.VerifierNodeResult, len(f.writers))
	outstandingIdx := make([][]int, len(f.writers))
	for i, data := range ccvDataList {
		for a := range f.writers {
			if f.isAcked(f.writers[a].label, data.MessageID) {
				continue
			}
			outstanding[a] = append(outstanding[a], data)
			outstandingIdx[a] = append(outstandingIdx[a], i)
		}
	}

	perAggregator := make([][]protocol.WriteResult, len(f.writers))
	for a := range f.writers {
		perAggregator[a] = make([]protocol.WriteResult, len(ccvDataList))
	}

	var wg sync.WaitGroup
	for a := range f.writers {
		if len(outstanding[a]) == 0 {
			continue
		}
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			results := f.writeToAggregator(ctx, f.writers[a], outstanding[a])
			for k, r := range results {
				idx := outstandingIdx[a][k]
				perAggregator[a][idx] = r
				if r.Status == protocol.WriteSuccess {
					f.recordAck(f.writers[a].label, r.Input.MessageID)
				}
			}
		}(a)
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
//   - success only when every aggregator acked the item (including acks learned on earlier
//     attempts, so a retry that already satisfied some aggregators can complete once the rest
//     catch up);
//   - on failure, retryable unless any aggregator returned a non-retryable error (retrying
//     cannot help that aggregator, so the item is failed permanently and logged distinctly).
//
// A fully acked item is dropped from the ack tracking: the write is complete and the queue will
// not retry it, so keeping the entry would only grow memory without bound.
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
			if f.isAcked(f.writers[a].label, data.MessageID) {
				continue
			}
			r := perAggregator[a][i]
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
			// Every aggregator confirmed this message; forget it so the ack tracking stays
			// bounded. The item will not be retried, so these entries are never read again.
			for a := range f.writers {
				f.forgetAck(f.writers[a].label, data.MessageID)
			}
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

// isAcked reports whether the given aggregator has already confirmed the message. A
// zero-value FanOutWriter (e.g. one built directly in a test) has no tracking and is treated
// as having no acks, so every item is still attempted.
func (f *FanOutWriter) isAcked(label string, msg protocol.Bytes32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acked == nil {
		return false
	}
	_, ok := f.acked[label][msg.String()]
	return ok
}

// recordAck marks the message as confirmed by the aggregator, lazily creating the tracking
// maps so the writer stays usable even when constructed without them.
func (f *FanOutWriter) recordAck(label string, msg protocol.Bytes32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acked == nil {
		f.acked = make(map[string]map[string]struct{})
	}
	agg := f.acked[label]
	if agg == nil {
		agg = make(map[string]struct{})
		f.acked[label] = agg
	}
	agg[msg.String()] = struct{}{}
}

// forgetAck removes the message from the aggregator's confirmed set. Used to bound memory
// once every aggregator has acked a message and the item will not be retried.
func (f *FanOutWriter) forgetAck(label string, msg protocol.Bytes32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if agg, ok := f.acked[label]; ok {
		delete(agg, msg.String())
	}
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
