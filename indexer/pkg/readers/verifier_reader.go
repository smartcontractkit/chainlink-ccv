package readers

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
)

var _ common.VerifierReader = (*verifierReader)(nil)

type verifierReader struct {
	demux   *common.Demultiplexer[protocol.Bytes32, protocol.CCVData]
	batchCh chan batcher.BatchResult[protocol.Bytes32]
	batcher *batcher.Batcher[protocol.Bytes32]
}

func NewVerifierReader(ctx context.Context) common.VerifierReader {
	batchCh := make(chan batcher.BatchResult[protocol.Bytes32])

	return &verifierReader{
		demux:   common.NewDemultiplexer[protocol.Bytes32, protocol.CCVData](),
		batchCh: batchCh,
		batcher: batcher.NewBatcher(ctx, 100, time.Second*1, batchCh),
	}
}

func (v *verifierReader) ProcessMessage(messageID protocol.Bytes32) chan common.Result[protocol.CCVData] {
	v.batcher.Add(messageID)
	return v.demux.Create(messageID)
}

func (v *verifierReader) Start(ctx context.Context) error {
	go v.run(ctx)
	return nil
}

func (v *verifierReader) run(ctx context.Context) {
	for {
		select {
		case batch := <-v.batchCh:
			respMap := v.callVerifier(batch.Items)

			// Itterate over the responses and send the responses back to the caller
			for msgID, verificationResult := range respMap {
				v.demux.Resolve(msgID, verificationResult.Value(), verificationResult.Err())
			}
		case <-ctx.Done():
			return
		}
	}
}

func (v *verifierReader) callVerifier(batch []protocol.Bytes32) map[protocol.Bytes32]common.Result[protocol.CCVData] {
	return nil
}

func (v *verifierReader) Close() error {
	return nil
}
