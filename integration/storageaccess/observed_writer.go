package storageaccess

import (
	"context"
	"errors"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.CCVNodeDataWriter = (*observedOffchainWriter)(nil)

type observedOffchainWriter struct {
	protocol.CCVNodeDataWriter

	verifierID string
	// targetLabel scopes this observer to a single target offchain and is
	// emitted as the "target" label on metrics/logs.
	targetLabel string
	lggr        logger.Logger
	monitoring  verifier.Monitoring
}

func NewObservedOffchainWriter(
	delegate protocol.CCVNodeDataWriter,
	verifierID string,
	lggr logger.Logger,
	monitoring verifier.Monitoring,
) protocol.CCVNodeDataWriter {
	return &observedOffchainWriter{
		CCVNodeDataWriter: delegate,
		verifierID:        verifierID,
		lggr:              lggr,
		monitoring:        monitoring,
	}
}

// NewObservedAggregatorWriter wraps a single aggregator's writer, tagging its metrics and logs
// with an "target" label so per-target write health is observable independently of the
// fan-out aggregate.
func NewObservedAggregatorWriter(
	delegate protocol.CCVNodeDataWriter,
	verifierID string,
	targetLabel string,
	lggr logger.Logger,
	monitoring verifier.Monitoring,
) (protocol.CCVNodeDataWriter, error) {
	if targetLabel == "" {
		return nil, errors.New("target label is required")
	}

	return &observedOffchainWriter{
		CCVNodeDataWriter: delegate,
		verifierID:        verifierID,
		targetLabel:       targetLabel,
		lggr:              logger.With(lggr, "target", targetLabel),
		monitoring:        monitoring,
	}, nil
}

// metrics returns the metric labeler scoped to this observer's verifier_id and (when set)
// aggregator label.
func (o *observedOffchainWriter) metrics() verifier.MetricLabeler {
	return o.monitoring.
		Metrics().
		With("verifier_id", o.verifierID).
		With("target", o.targetLabel)
}

func (o *observedOffchainWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
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
