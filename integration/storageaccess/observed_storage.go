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

func (o *observedStorageWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) error {
	start := time.Now()

	err := o.CCVNodeDataWriter.WriteCCVNodeData(ctx, ccvDataList)
	if err != nil {
		o.monitoring.Metrics().IncrementStorageWriteErrors(ctx)
		o.lggr.Errorw("Error storing CCV data batch",
			"error", err,
			"batchSize", len(ccvDataList),
		)
		for _, ccvData := range ccvDataList {
			o.lggr.Errorw("Failed to store CCV data in batch",
				"messageID", ccvData.MessageID,
				"sequenceNumber", ccvData.Message.SequenceNumber,
				"sourceChain", ccvData.Message.SourceChainSelector,
			)
		}
		return err
	}

	o.monitoring.Metrics().
		With("verifier_id", o.verifierID).
		RecordStorageWriteDuration(ctx, time.Since(start))

	return nil
}
