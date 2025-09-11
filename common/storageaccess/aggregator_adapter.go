package storageaccess

import (
	"context"
	"fmt"
	"math"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AggregatorWriter struct {
	client aggregator.AggregatorClient
	conn   *grpc.ClientConn
	lggr   logger.Logger
}

func mapReceiptBlob(receiptBlob types.ReceiptWithBlob) (*aggregator.ReceiptBlob, error) {
	return &aggregator.ReceiptBlob{
		Issuer:            receiptBlob.Issuer[:],
		Blob:              receiptBlob.Blob[:],
		DestGasLimit:      receiptBlob.DestGasLimit,
		DestBytesOverhead: receiptBlob.DestBytesOverhead,
		ExtraArgs:         receiptBlob.ExtraArgs,
	}, nil
}

func mapReceiptBlobs(receiptBlobs []types.ReceiptWithBlob) ([]*aggregator.ReceiptBlob, error) {
	var result []*aggregator.ReceiptBlob
	for _, blob := range receiptBlobs {
		mapped, err := mapReceiptBlob(blob)
		if err != nil {
			return nil, err
		}
		if mapped != nil {
			result = append(result, mapped)
		}
	}
	return result, nil
}

// WriteCCVData implements common.OffchainStorageWriter.
func (a *AggregatorWriter) WriteCCVData(ctx context.Context, ccvDataList []types.CCVData) error {
	a.lggr.Info("Storing CCV data using aggregator ", "count", len(ccvDataList))
	for _, ccvData := range ccvDataList {
		receiptBlobs, err := mapReceiptBlobs(ccvData.ReceiptBlobs)
		if err != nil {
			return err
		}

		res, err := a.client.WriteCommitCCVNodeData(ctx, &aggregator.WriteCommitCCVNodeDataRequest{
			CcvNodeData: &aggregator.MessageWithCCVNodeData{
				MessageId:             ccvData.MessageID[:],
				SourceVerifierAddress: ccvData.SourceVerifierAddress[:],
				DestVerifierAddress:   ccvData.DestVerifierAddress[:],
				CcvData:               ccvData.CCVData,
				BlobData:              ccvData.BlobData,
				Timestamp:             ccvData.Timestamp,
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
				ReceiptBlobs: receiptBlobs,
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

func (a *AggregatorWriter) GetStats() map[string]any {
	return make(map[string]any)
}

// Close closes the gRPC connection to the aggregator server.
func (a *AggregatorWriter) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// NewAggregatorWriter creates instance of AggregatorWriter that satisfies OffchainStorageWriter interface.
func NewAggregatorWriter(address string, lggr logger.Logger) (*AggregatorWriter, error) {
	// Create a gRPC connection to the aggregator server
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &AggregatorWriter{
		client: aggregator.NewAggregatorClient(conn),
		conn:   conn,
		lggr:   lggr,
	}, nil
}

type AggregatorReader struct {
	client aggregator.CCVDataClient
	lggr   logger.Logger
	conn   *grpc.ClientConn
	token  string
	since  int64
}

// NewAggregatorReader creates instance of AggregatorReader that satisfies OffchainStorageReader interface.
func NewAggregatorReader(address string, lggr logger.Logger, since int64) (*AggregatorReader, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &AggregatorReader{
		client: aggregator.NewCCVDataClient(conn),
		conn:   conn,
		lggr:   lggr,
		since:  since,
	}, nil
}

// Close closes the gRPC connection to the aggregator server.
func (a *AggregatorReader) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

func mapMessage(msg *aggregator.Message) (types.Message, error) {
	if msg == nil {
		return types.Message{}, nil
	}
	result := types.Message{
		SourceChainSelector: types.ChainSelector(msg.SourceChainSelector),
		DestChainSelector:   types.ChainSelector(msg.DestChainSelector),
		SequenceNumber:      types.SeqNum(msg.SequenceNumber),
		OnRampAddress:       msg.OnRampAddress[:],
		OffRampAddress:      msg.OffRampAddress[:],
		Sender:              msg.Sender[:],
		Receiver:            msg.Receiver[:],
		DestBlob:            msg.DestBlob[:],
		TokenTransfer:       msg.TokenTransfer[:],
		Data:                msg.Data[:],
	}

	if msg.Version > math.MaxUint8 {
		return types.Message{}, fmt.Errorf("field Version %d exceeds uint8 max", msg.Version)
	}
	result.Version = uint8(msg.Version)
	if msg.OnRampAddressLength > math.MaxUint8 {
		return types.Message{}, fmt.Errorf("field OnRampAddressLength %d exceeds uint8 max",
			msg.OnRampAddressLength)
	}
	result.OnRampAddressLength = uint8(msg.OnRampAddressLength)
	if msg.OffRampAddressLength > math.MaxUint8 {
		return types.Message{}, fmt.Errorf("field OffRampAddressLength %d exceeds uint8 max",
			msg.OffRampAddressLength)
	}
	result.OffRampAddressLength = uint8(msg.OffRampAddressLength)
	if msg.Finality > math.MaxUint16 {
		return types.Message{}, fmt.Errorf("field Finality %d exceeds uint16 max", msg.Finality)
	}
	result.Finality = uint16(msg.Finality)
	if msg.SenderLength > math.MaxUint8 {
		return types.Message{}, fmt.Errorf("field SenderLength %d exceeds uint8 max", msg.SenderLength)
	}
	result.SenderLength = uint8(msg.SenderLength)
	if msg.ReceiverLength > math.MaxUint8 {
		return types.Message{}, fmt.Errorf("field ReceiverLength %d exceeds uint8 max", msg.ReceiverLength)
	}
	result.ReceiverLength = uint8(msg.ReceiverLength)
	if msg.DestBlobLength > math.MaxUint16 {
		return types.Message{}, fmt.Errorf("field DestBlobLength %d exceeds uint16 max", msg.DestBlobLength)
	}
	result.DestBlobLength = uint16(msg.DestBlobLength)
	if msg.TokenTransferLength > math.MaxUint16 {
		return types.Message{}, fmt.Errorf("field TokenTransferLength %d exceeds uint16 max", msg.TokenTransferLength)
	}
	result.TokenTransferLength = uint16(msg.TokenTransferLength)
	if msg.DataLength > math.MaxUint16 {
		return types.Message{}, fmt.Errorf("field DataLength %d exceeds uint16 max", msg.DataLength)
	}
	result.DataLength = uint16(msg.DataLength)

	return result, nil
}

// ReadCCVData returns the next available CCV data entries.
func (a *AggregatorReader) ReadCCVData(ctx context.Context) ([]types.QueryResponse, error) {
	resp, err := a.client.GetMessagesSince(ctx, &aggregator.GetMessagesSinceRequest{
		Since: a.since,
	})
	if err != nil {
		return nil, fmt.Errorf("error calling GetMessagesSince: %w", err)
	}

	// Convert the response to []types.QueryResponse
	results := make([]types.QueryResponse, 0, len(resp.Results))
	for i, result := range resp.Results {
		msg, err := mapMessage(result.Message)
		if err != nil {
			return nil, fmt.Errorf("error mapping message at index %d: %w", i, err)
		}
		results[i] = types.QueryResponse{
			Timestamp: nil,
			Data: types.CCVData{
				Message:   msg,
				CCVData:   result.CcvData,
				Timestamp: result.Timestamp,
			},
		}
	}

	// Update token for next call.
	a.token = resp.NextToken

	return results, nil
}
