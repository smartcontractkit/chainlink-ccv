package storageaccess

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type AggregatorWriter struct {
	client pb.AggregatorClient
	conn   *grpc.ClientConn
	lggr   logger.Logger
}

func mapReceiptBlob(receiptBlob protocol.ReceiptWithBlob) (*pb.ReceiptBlob, error) {
	return &pb.ReceiptBlob{
		Issuer:            receiptBlob.Issuer[:],
		Blob:              receiptBlob.Blob[:],
		DestGasLimit:      receiptBlob.DestGasLimit,
		DestBytesOverhead: receiptBlob.DestBytesOverhead,
		ExtraArgs:         receiptBlob.ExtraArgs,
	}, nil
}

func mapReceiptBlobs(receiptBlobs []protocol.ReceiptWithBlob) ([]*pb.ReceiptBlob, error) {
	var result []*pb.ReceiptBlob
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

func mapCCVDataToCCVNodeDataProto(ccvData protocol.CCVData) (*pb.WriteCommitteeVerifierNodeResultRequest, error) {
	receiptBlobs, err := mapReceiptBlobs(ccvData.ReceiptBlobs)
	if err != nil {
		return nil, err
	}

	return &pb.WriteCommitteeVerifierNodeResultRequest{
		CcvNodeData: &pb.CommitteeVerifierNodeResult{
			MessageId:             ccvData.MessageID[:],
			SourceVerifierAddress: ccvData.SourceVerifierAddress[:],
			CcvData:               ccvData.CCVData,
			BlobData:              ccvData.BlobData,
			Timestamp:             ccvData.Timestamp.UnixMilli(),
			Message: &pb.Message{
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
				GasLimit:             ccvData.Message.GasLimit,
			},
			ReceiptBlobs: receiptBlobs,
		},
	}, nil
}

// WriteCCVNodeData writes CCV data to the aggregator via gRPC.
func (a *AggregatorWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.CCVData) error {
	a.lggr.Info("Storing CCV data using aggregator ", "count", len(ccvDataList))

	requests := make([]*pb.WriteCommitteeVerifierNodeResultRequest, 0, len(ccvDataList))
	for _, ccvData := range ccvDataList {
		req, err := mapCCVDataToCCVNodeDataProto(ccvData)
		// FIXME: Single bad entry shouldn't fail the whole batch, it might lead to infinitely retrying the same bad entry
		// and making no progress
		if err != nil {
			return err
		}
		requests = append(requests, req)
	}

	responses, err := a.client.BatchWriteCommitteeVerifierNodeResult(
		ctx, &pb.BatchWriteCommitteeVerifierNodeResultRequest{
			Requests: requests,
		},
	)
	if err != nil {
		return fmt.Errorf("error calling BatchWriteCommitteeVerifierNodeResult: %w", err)
	}

	// FIXME: AggregatorWriter should expose underlying errors (per single ccvDataRequest) to the caller,
	// so that caller can decide what to do with failed entries (i.e., retry only failed ones).
	for i, resp := range responses.Responses {
		messageID := "unknown"
		if i < len(ccvDataList) {
			messageID = ccvDataList[i].MessageID.String()
		}

		if resp.Status != pb.WriteStatus_SUCCESS {
			a.lggr.Info("BatchWriteCommitteeVerifierNodeResult", "status", resp.Status)
			continue
		}
		a.lggr.Infow("Successfully stored CCV data", "messageID", messageID)
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

// WriteChainStatus writes chain statuses to the aggregator.
func (a *AggregatorWriter) WriteChainStatus(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	// HMAC authentication is automatically handled by the client interceptor

	// Convert chain statuses to protobuf format
	pbStatuses := make([]*pb.ChainStatus, 0, len(statuses))
	for _, status := range statuses {
		pbStatuses = append(pbStatuses, &pb.ChainStatus{
			ChainSelector:        uint64(status.ChainSelector),
			FinalizedBlockHeight: status.BlockNumber.Uint64(),
			Disabled:             status.Disabled,
		})
	}

	req := &pb.WriteChainStatusRequest{
		Statuses: pbStatuses,
	}

	// Make the gRPC call
	resp, err := a.client.WriteChainStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to write chain status: %w", err)
	}

	if resp.Status != pb.WriteStatus_SUCCESS {
		return fmt.Errorf("chain status write failed with status: %s", resp.Status.String())
	}

	a.lggr.Debugw("Successfully wrote chain statuses", "count", len(statuses))

	return nil
}

// NewAggregatorWriter creates instance of AggregatorWriter that satisfies OffchainStorageWriter interface.
func NewAggregatorWriter(address string, lggr logger.Logger, hmacConfig *hmac.ClientConfig) (*AggregatorWriter, error) {
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	if hmacConfig != nil {
		dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(hmac.NewClientInterceptor(hmacConfig)))
	}

	// Create a gRPC connection to the aggregator server with HMAC authentication
	conn, err := grpc.NewClient(
		address,
		dialOptions...,
	)
	if err != nil {
		return nil, err
	}

	return &AggregatorWriter{
		client: pb.NewAggregatorClient(conn),
		conn:   conn,
		lggr:   lggr,
	}, nil
}

type AggregatorReader struct {
	client                 pb.VerifierResultAPIClient
	messageDiscoveryClient pb.MessageDiscoveryClient
	lggr                   logger.Logger
	conn                   *grpc.ClientConn
	since                  int64
}

// NewAggregatorReader creates instance of AggregatorReader that satisfies OffchainStorageReader interface.
func NewAggregatorReader(address string, lggr logger.Logger, since int64, hmacConfig *hmac.ClientConfig) (*AggregatorReader, error) {
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	if hmacConfig != nil {
		dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(hmac.NewClientInterceptor(hmacConfig)))
	}

	// Create a gRPC connection to the aggregator server with HMAC authentication
	conn, err := grpc.NewClient(
		address,
		dialOptions...,
	)
	if err != nil {
		return nil, err
	}

	return &AggregatorReader{
		client:                 pb.NewVerifierResultAPIClient(conn),
		messageDiscoveryClient: pb.NewMessageDiscoveryClient(conn),
		conn:                   conn,
		lggr:                   logger.With(lggr, "aggregatorAddress", address),
		since:                  since,
	}, nil
}

// Close closes the gRPC connection to the aggregator server.
func (a *AggregatorReader) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// ReadChainStatus reads chain statuses from the aggregator.
// Returns map of chainSelector -> ChainStatusInfo. Missing chains are not included in the map.
func (a *AggregatorReader) ReadChainStatus(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	// Convert chainSelectors to uint64 slice
	selectors := make([]uint64, len(chainSelectors))
	for i, selector := range chainSelectors {
		selectors[i] = uint64(selector)
	}

	// Create read request
	req := &pb.ReadChainStatusRequest{
		ChainSelectors: selectors,
	}

	// Create aggregator client for chain status operations (different from CCV data client)
	aggregatorClient := pb.NewAggregatorClient(a.conn)

	// Make the gRPC call
	resp, err := aggregatorClient.ReadChainStatus(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain status: %w", err)
	}

	result := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
	for _, chainStatus := range resp.Statuses {
		selector := protocol.ChainSelector(chainStatus.ChainSelector)
		result[selector] = &protocol.ChainStatusInfo{
			ChainSelector: selector,
			BlockNumber:   new(big.Int).SetUint64(chainStatus.FinalizedBlockHeight),
			Disabled:      chainStatus.Disabled,
		}
	}

	return result, nil
}

func mapMessage(msg *pb.Message) (protocol.Message, error) {
	if msg == nil {
		return protocol.Message{}, nil
	}
	result := protocol.Message{
		SourceChainSelector: protocol.ChainSelector(msg.SourceChainSelector),
		DestChainSelector:   protocol.ChainSelector(msg.DestChainSelector),
		Nonce:               protocol.Nonce(msg.Nonce),
		OnRampAddress:       msg.OnRampAddress[:],
		OffRampAddress:      msg.OffRampAddress[:],
		Sender:              msg.Sender[:],
		Receiver:            msg.Receiver[:],
		DestBlob:            msg.DestBlob[:],
		TokenTransfer:       msg.TokenTransfer[:],
		Data:                msg.Data[:],
		GasLimit:            msg.GasLimit,
	}

	if msg.Version > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field Version %d exceeds uint8 max", msg.Version)
	}
	result.Version = uint8(msg.Version)
	if msg.OnRampAddressLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field OnRampAddressLength %d exceeds uint8 max",
			msg.OnRampAddressLength)
	}
	result.OnRampAddressLength = uint8(msg.OnRampAddressLength)
	if msg.OffRampAddressLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field OffRampAddressLength %d exceeds uint8 max",
			msg.OffRampAddressLength)
	}
	result.OffRampAddressLength = uint8(msg.OffRampAddressLength)
	if msg.Finality > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field Finality %d exceeds uint16 max", msg.Finality)
	}
	result.Finality = uint16(msg.Finality)
	if msg.SenderLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field SenderLength %d exceeds uint8 max", msg.SenderLength)
	}
	result.SenderLength = uint8(msg.SenderLength)
	if msg.ReceiverLength > math.MaxUint8 {
		return protocol.Message{}, fmt.Errorf("field ReceiverLength %d exceeds uint8 max", msg.ReceiverLength)
	}
	result.ReceiverLength = uint8(msg.ReceiverLength)
	if msg.DestBlobLength > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field DestBlobLength %d exceeds uint16 max", msg.DestBlobLength)
	}
	result.DestBlobLength = uint16(msg.DestBlobLength)
	if msg.TokenTransferLength > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field TokenTransferLength %d exceeds uint16 max", msg.TokenTransferLength)
	}
	result.TokenTransferLength = uint16(msg.TokenTransferLength)
	if msg.DataLength > math.MaxUint16 {
		return protocol.Message{}, fmt.Errorf("field DataLength %d exceeds uint16 max", msg.DataLength)
	}
	result.DataLength = uint16(msg.DataLength)

	return result, nil
}

// ReadCCVData returns the next available CCV data entries.
func (a *AggregatorReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	resp, err := a.messageDiscoveryClient.GetMessagesSince(ctx, &pb.GetMessagesSinceRequest{
		SinceSequence: a.since,
	})
	if err != nil {
		return nil, fmt.Errorf("error calling GetMessagesSince: %w", err)
	}

	a.lggr.Debugw("Got messages since", "count", len(resp.Results), "since", a.since)
	// Convert the response to []types.QueryResponse
	results := make([]protocol.QueryResponse, 0, len(resp.Results))
	tempSince := a.since
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

		sequence := result.Sequence
		if sequence >= tempSince {
			tempSince = sequence + 1
		}

		receiptBlobs := []protocol.ReceiptWithBlob{}
		for _, receipt := range result.GetReceiptBlobsFromMajority() {
			receiptBlobs = append(receiptBlobs, protocol.ReceiptWithBlob{
				Issuer:            protocol.UnknownAddress(receipt.Issuer),
				Blob:              protocol.ByteSlice(receipt.Blob),
				ExtraArgs:         protocol.ByteSlice(receipt.ExtraArgs),
				DestGasLimit:      receipt.DestGasLimit,
				DestBytesOverhead: receipt.DestBytesOverhead,
				FeeTokenAmount:    big.NewInt(0), // for some reason doesn't exist in the pb message
			})
		}

		results = append(results, protocol.QueryResponse{
			Timestamp: nil,
			Data: protocol.CCVData{
				SourceVerifierAddress: result.GetSourceVerifierAddress(),
				DestVerifierAddress:   result.GetDestVerifierAddress(),
				CCVData:               result.CcvData,
				// BlobData & ReceiptBlobs need to be added
				ReceiptBlobs:        receiptBlobs,
				Message:             msg,
				Nonce:               msg.Nonce,
				SourceChainSelector: msg.SourceChainSelector,
				DestChainSelector:   msg.DestChainSelector,
				Timestamp:           time.UnixMilli(result.Timestamp),
				MessageID:           messageID,
			},
		})
	}

	a.since = tempSince

	return results, nil
}

func (a *AggregatorReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.CCVData, error) {
	messageIDsBytes := make([][]byte, 0, len(messageIDs))
	for _, id := range messageIDs {
		messageIDsBytes = append(messageIDsBytes, id[:])
	}

	resp, err := a.client.GetVerifierResultsForMessage(ctx, &pb.GetVerifierResultsForMessageRequest{
		MessageIds: messageIDsBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("error calling GetVerifierResultsForMessage: %s", err)
	}

	a.lggr.Debugw("GetVerifierResultsForMessage", "count", len(resp.Results), "messageIDs", messageIDs)
	results := make(map[protocol.Bytes32]protocol.CCVData)
	for i, result := range resp.Results {
		msg, err := mapMessage(result.Message)
		if err != nil {
			return nil, fmt.Errorf("error mapping message at index %d: %w", i, err)
		}

		messageID, err := msg.MessageID()
		if err != nil {
			return nil, fmt.Errorf("error computing message ID at index %d: %w", i, err)
		}

		results[messageID] = protocol.CCVData{
			SourceVerifierAddress: protocol.UnknownAddress(result.SourceVerifierAddress),
			DestVerifierAddress:   protocol.UnknownAddress(result.DestVerifierAddress),
			CCVData:               protocol.ByteSlice(result.CcvData),
			BlobData:              protocol.ByteSlice{},         // Unavailable in API
			ReceiptBlobs:          []protocol.ReceiptWithBlob{}, // Unavailable in API
			Message:               msg,
			Nonce:                 msg.Nonce,
			SourceChainSelector:   msg.SourceChainSelector,
			DestChainSelector:     msg.DestChainSelector,
			Timestamp:             time.UnixMilli(result.Timestamp),
			MessageID:             messageID,
		}
	}

	return results, nil
}
