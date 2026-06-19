package storageaccess

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.CCVNodeDataWriter = (*observedStorageWriter)(nil)

type observedStorageWriter struct {
	protocol.CCVNodeDataWriter

	verifierID string
	// aggregatorLabel, when non-empty, scopes this observer to a single aggregator and is
	// emitted as the "aggregator" label on metrics/logs. Empty means the observer covers the
	// aggregate (fan-out-wide) outcome.
	aggregatorLabel string
	lggr            logger.Logger
	monitoring      verifier.Monitoring
}

func NewObservedStorageWriter(
	delegate protocol.CCVNodeDataWriter,
	verifierID string,
	lggr logger.Logger,
	monitoring verifier.Monitoring,
) protocol.CCVNodeDataWriter {
	return &observedStorageWriter{
		CCVNodeDataWriter: delegate,
		verifierID:        verifierID,
		lggr:              lggr,
		monitoring:        monitoring,
	}
}

// NewObservedAggregatorWriter wraps a single aggregator's writer, tagging its metrics and logs
// with an "aggregator" label so per-aggregator write health is observable independently of the
// fan-out aggregate.
func NewObservedAggregatorWriter(
	delegate protocol.CCVNodeDataWriter,
	verifierID string,
	aggregatorLabel string,
	lggr logger.Logger,
	monitoring verifier.Monitoring,
) protocol.CCVNodeDataWriter {
	return &observedStorageWriter{
		CCVNodeDataWriter: delegate,
		verifierID:        verifierID,
		aggregatorLabel:   aggregatorLabel,
		lggr:              logger.With(lggr, "aggregator", aggregatorLabel),
		monitoring:        monitoring,
	}
}

// metrics returns the metric labeler scoped to this observer's verifier_id and (when set)
// aggregator label.
func (o *observedStorageWriter) metrics() verifier.MetricLabeler {
	m := o.monitoring.Metrics().With("verifier_id", o.verifierID)
	if o.aggregatorLabel != "" {
		m = m.With("aggregator", o.aggregatorLabel)
	}
	return m
}

func (o *observedStorageWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	start := time.Now()

	results, err := o.CCVNodeDataWriter.WriteCCVNodeData(ctx, ccvDataList)

	// Count failures in the results
	failureCount := 0
	for _, result := range results {
		if result.Status == protocol.WriteFailure {
			failureCount++
			o.lggr.Errorw("Failed to store CCV data in batch",
				"verifier_id", o.verifierID,
				"messageID", result.Input.MessageID,
				"sequenceNumber", result.Input.Message.SequenceNumber,
				"sourceChain", result.Input.Message.SourceChainSelector,
				"error", result.Error,
				"retryable", result.Retryable,
			)
		}
	}

	metrics := o.metrics()
	if failureCount > 0 {
		metrics.IncrementStorageWriteErrors(ctx)
		o.lggr.Errorw("Error storing CCV data batch",
			"verifier_id", o.verifierID,
			"error", err,
			"batchSize", len(ccvDataList),
			"failureCount", failureCount,
		)
	}

	metrics.RecordStorageWriteDuration(ctx, time.Since(start))

	return results, err
}
