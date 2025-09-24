package storageaccess

import (
	"context"
	"fmt"
	"math"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	aggregator "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
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

func mapCCVDataToCCVNodeDataProto(ccvData types.CCVData) (*aggregator.WriteCommitCCVNodeDataRequest, error) {
	receiptBlobs, err := mapReceiptBlobs(ccvData.ReceiptBlobs)
	if err != nil {
		return nil, err
	}
	return &aggregator.WriteCommitCCVNodeDataRequest{
		CcvNodeData: &aggregator.MessageWithCCVNodeData{
			MessageId:             ccvData.MessageID[:],
			SourceVerifierAddress: ccvData.SourceVerifierAddress[:],
			CcvData:               ccvData.CCVData,
			BlobData:              ccvData.BlobData,
			Timestamp:             ccvData.Timestamp,
			Message: &aggregator.Message{
				Version:              uint32(ccvData.Message.Version),
				SourceChainSelector:  uint64(ccvData.Message.SourceChainSelector),
				DestChainSelector:    uint64(ccvData.Message.DestChainSelector),
				Nonce:                uint64(ccvData.Message.Nonce),
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
	}, nil
}

// WriteCCVNodeData writes CCV data to the aggregator via gRPC.
func (a *AggregatorWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []types.CCVData) error {
	a.lggr.Info("Storing CCV data using aggregator ", "count", len(ccvDataList))
	for _, ccvData := range ccvDataList {
		req, err := mapCCVDataToCCVNodeDataProto(ccvData)
		if err != nil {
			return err
		}
		responses, err := a.client.BatchWriteCommitCCVNodeData(ctx, &aggregator.BatchWriteCommitCCVNodeDataRequest{
			Requests: []*aggregator.WriteCommitCCVNodeDataRequest{req},
		})
		if err != nil {
			return fmt.Errorf("error calling BatchWriteCommitCCVNodeData: %w", err)
		}
		for _, resp := range responses.Responses {
			if resp.Status != aggregator.WriteStatus_SUCCESS {
				return fmt.Errorf("failed to write CCV data for message ID %x: status %s", ccvData.MessageID, resp.Status.String())
			}
			a.lggr.Infow("Successfully stored CCV data", "messageID", ccvData.MessageID)
		}
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
		Nonce:               types.Nonce(msg.Nonce),
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
		Since:     a.since,
		NextToken: a.token,
	})
	if err != nil {
		return nil, fmt.Errorf("error calling GetMessagesSince: %w", err)
	}

	a.lggr.Debugw("Got messages since", "count", len(resp.Results))
	// Convert the response to []types.QueryResponse
	results := make([]types.QueryResponse, 0, len(resp.Results))
	for i, result := range resp.Results {
		msg, err := mapMessage(result.Message)
		if err != nil {
			return nil, fmt.Errorf("error mapping message at index %d: %w", i, err)
		}

		// Compute MessageId from the message
		messageID, err := msg.MessageID()
		if err != nil {
			return nil, fmt.Errorf("error computing message ID at index %d: %w", i, err)
		}

		results = append(results, types.QueryResponse{
			Timestamp: nil,
			Data: types.CCVData{
				SourceVerifierAddress: result.GetSourceVerifierAddress(),
				DestVerifierAddress:   result.GetDestVerifierAddress(),
				CCVData:               result.CcvData,
				// BlobData & ReceiptBlobs need to be added
				Message:             msg,
				Nonce:               msg.Nonce,
				SourceChainSelector: msg.SourceChainSelector,
				DestChainSelector:   msg.DestChainSelector,
				Timestamp:           result.Timestamp,
				MessageID:           messageID,
			},
		})
	}

	// Update token for next call.
	a.since = a.getNextTimestamp(results)
	a.token = resp.NextToken

	return results, nil
}

func (a *AggregatorReader) getNextTimestamp(results []types.QueryResponse) int64 {
	if len(results) > 0 {
		return results[len(results)-1].Data.Timestamp + 1
	}
	return time.Now().Unix()
}
