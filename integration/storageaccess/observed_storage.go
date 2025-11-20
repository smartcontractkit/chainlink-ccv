package storageaccess

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.CCVNodeDataWriter = (*observedStorage)(nil)

type observedStorage struct {
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
	return &observedStorage{
		CCVNodeDataWriter: delegate,
		verifierID:        verifierID,
		lggr:              lggr,
		monitoring:        monitoring,
	}
}

func (o *observedStorage) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.CCVData) error {
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
				"nonce", ccvData.Nonce,
				"sourceChain", ccvData.SourceChainSelector,
			)
		}
		return err
	}

	o.monitoring.Metrics().
		With("verifier_id", o.verifierID).
		RecordStorageWriteDuration(ctx, time.Since(start))

	return nil
}
