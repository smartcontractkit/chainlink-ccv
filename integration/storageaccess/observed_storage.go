package storageaccess

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.CCVNodeDataWriter = (*observedStorageWriter)(nil)

type observedStorageWriter struct {
	protocol.CCVNodeDataWriter

	verifierID string
	lggr       logger.Logger
	monitoring verifier.Monitoring
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

func (o *observedStorageWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	start := time.Now()

	results, err := o.CCVNodeDataWriter.WriteCCVNodeData(ctx, ccvDataList)

	// Count failures in the results
	failureCount := 0
	for _, result := range results {
		if result.Status == protocol.WriteFailure {
			failureCount++
			o.lggr.Errorw("Failed to store CCV data in batch",
				"messageID", result.Input.MessageID,
				"sequenceNumber", result.Input.Message.SequenceNumber,
				"sourceChain", result.Input.Message.SourceChainSelector,
				"error", result.Error,
				"retryable", result.Retryable,
			)
		}
	}

	if failureCount > 0 {
		o.monitoring.Metrics().IncrementStorageWriteErrors(ctx)
		o.lggr.Errorw("Error storing CCV data batch",
			"error", err,
			"batchSize", len(ccvDataList),
			"failureCount", failureCount,
		)
	}

	o.monitoring.Metrics().
		With("verifier_id", o.verifierID).
		RecordStorageWriteDuration(ctx, time.Since(start))

	return results, err
}
