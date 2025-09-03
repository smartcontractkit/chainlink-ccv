package storageaccess

import (
	"context"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AggregatorWriterAdapter struct {
	client        aggregator.AggregatorClient
	conn          *grpc.ClientConn
	lggr          logger.Logger
	participantID string
	committeeID   string
}

// StoreCCVData implements common.OffchainStorageWriter.
func (a *AggregatorWriterAdapter) StoreCCVData(ctx context.Context, ccvDataList []common.CCVData) error {
	a.lggr.Info("Storing CCV data using aggregator ", "count", len(ccvDataList))
	for _, ccvData := range ccvDataList {
		res, err := a.client.WriteCommitVerification(ctx, &aggregator.WriteCommitVerificationRequest{
			ParticipantId: a.participantID,
			CommitteeId:   a.committeeID,
			CommitVerificationRecord: &aggregator.CommitVerificationRecord{
				MessageId:             ccvData.MessageID[:],
				SequenceNumber:        uint64(ccvData.SequenceNumber),
				SourceChainSelector:   uint64(ccvData.SourceChainSelector),
				DestChainSelector:     uint64(ccvData.DestChainSelector),
				SourceVerifierAddress: ccvData.SourceVerifierAddress[:],
				DestVerifierAddress:   ccvData.DestVerifierAddress[:],
				CcvData:               ccvData.CCVData,
				BlobData:              ccvData.BlobData,
				Timestamp:             uint64(ccvData.Timestamp),
				Message: &aggregator.Message{
					Version:              uint32(ccvData.Message.Version),
					SourceChainSelector:  uint64(ccvData.Message.SourceChainSelector),
					DestChainSelector:    uint64(ccvData.Message.DestChainSelector),
					SequenceNumber:       uint64(ccvData.Message.SequenceNumber),
					OnRampAddressLength:  uint32(ccvData.Message.OnRampAddressLength),
					OnRampAddress:        ccvData.Message.OnRampAddress[:],
					OffRampAddressLength: uint32(ccvData.Message.OffRampAddressLength),
					OffRampAddress:       ccvData.Message.OffRampAddress[:],
					Finality:             uint32(ccvData.Message.Finality),
					SenderLength:         uint32(ccvData.Message.SenderLength),
					Sender:               ccvData.Message.Sender[:],
					ReceiverLength:       uint32(ccvData.Message.ReceiverLength),
					Receiver:             ccvData.Message.Receiver[:],
					DestBlobLength:       uint32(ccvData.Message.DestBlobLength),
					DestBlob:             ccvData.Message.DestBlob[:],
					TokenTransferLength:  uint32(ccvData.Message.TokenTransferLength),
					TokenTransfer:        ccvData.Message.TokenTransfer[:],
					DataLength:           uint32(ccvData.Message.DataLength),
					Data:                 ccvData.Message.Data[:],
				},
			},
		})
		if err != nil {
			a.lggr.Errorw("failed to store CCV data", "error", err)
			return err
		}

		if res.GetStatus() != aggregator.WriteStatus_SUCCESS {
			a.lggr.Errorw("failed to store CCV data", "error", err)
			return err
		}
		a.lggr.Infof("Successfully stored CCV data with MessageID: %x", ccvData.MessageID)
	}
	return nil
}

func (a *AggregatorWriterAdapter) GetStats() map[string]interface{} {
	return map[string]interface{}{}
}

// Close closes the gRPC connection to the aggregator server.
func (a *AggregatorWriterAdapter) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

func CreateAggregatorAdapter(address string, lggr logger.Logger, participantID string, committeeID string) (*AggregatorWriterAdapter, error) {
	// Create a gRPC connection to the aggregator server
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &AggregatorWriterAdapter{
		client:        aggregator.NewAggregatorClient(conn),
		conn:          conn,
		lggr:          lggr,
		participantID: participantID,
		committeeID:   committeeID,
	}, nil
}
