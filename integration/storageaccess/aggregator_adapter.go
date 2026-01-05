package storageaccess

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	insecuregrpc "google.golang.org/grpc/credentials/insecure"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

const (
	AdapterMinTLSVersion = tls.VersionTLS13
)

type AggregatorWriter struct {
	client committeepb.CommitteeVerifierClient
	conn   *grpc.ClientConn
	lggr   logger.Logger
}

func mapCCVDataToCCVNodeDataProto(ccvData protocol.VerifierNodeResult) (*committeepb.WriteCommitteeVerifierNodeResultRequest, error) {
	// Convert CCV addresses to byte slices
	ccvAddresses := make([][]byte, len(ccvData.CCVAddresses))
	for i, addr := range ccvData.CCVAddresses {
		ccvAddresses[i] = addr[:]
	}

	message, err := v1.NewVerifierResultMessage(ccvData.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier result message: %w", err)
	}
	return &committeepb.WriteCommitteeVerifierNodeResultRequest{
		CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{
			CcvVersion:      ccvData.CCVVersion,
			CcvAddresses:    ccvAddresses,
			ExecutorAddress: ccvData.ExecutorAddress[:],
			Signature:       ccvData.Signature[:],
			Message:         message.Message,
		},
	}, nil
} // WriteCCVNodeData writes CCV data to the aggregator via gRPC.
func (a *AggregatorWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) error {
	a.lggr.Info("Storing CCV data using aggregator ", "count", len(ccvDataList))

	requests := make([]*committeepb.WriteCommitteeVerifierNodeResultRequest, 0, len(ccvDataList))
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
		ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
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

		if resp.Status != committeepb.WriteStatus_SUCCESS {
			a.lggr.Error("BatchWriteCommitteeVerifierNodeResult", "status", resp.Status)
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

// NewAggregatorWriter creates instance of AggregatorWriter that satisfies CCVNodeDataWriter interface.
// If insecure is true, TLS verification is disabled (only for testing).
func NewAggregatorWriter(address string, lggr logger.Logger, hmacConfig *hmac.ClientConfig, insecure bool) (*AggregatorWriter, error) {
	var dialOptions []grpc.DialOption
	if insecure {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecuregrpc.NewCredentials()))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: AdapterMinTLSVersion})))
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
		client: committeepb.NewCommitteeVerifierClient(conn),
		conn:   conn,
		lggr:   lggr,
	}, nil
}

type AggregatorReader struct {
	client                 verifierpb.VerifierClient
	messageDiscoveryClient msgdiscoverypb.MessageDiscoveryClient
	lggr                   logger.Logger
	conn                   *grpc.ClientConn
	since                  atomic.Int64
}

// NewAggregatorReader creates instance of AggregatorReader that satisfies OffchainStorageReader interface.
// If insecure is true, TLS verification is disabled (only for testing).
func NewAggregatorReader(address string, lggr logger.Logger, since int64, hmacConfig *hmac.ClientConfig, insecure bool) (*AggregatorReader, error) {
	var dialOptions []grpc.DialOption
	if insecure {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecuregrpc.NewCredentials()))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: AdapterMinTLSVersion})))
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

	aggregatorReader := &AggregatorReader{
		client:                 verifierpb.NewVerifierClient(conn),
		messageDiscoveryClient: msgdiscoverypb.NewMessageDiscoveryClient(conn),
		conn:                   conn,
		lggr:                   logger.With(lggr, "aggregatorAddress", address),
	}

	aggregatorReader.since.Store(since)
	return aggregatorReader, nil
}

func (a *AggregatorReader) GetSinceValue() int64 {
	return a.since.Load()
}

func (a *AggregatorReader) SetSinceValue(since int64) {
	a.since.Store(since)
}

// Close closes the gRPC connection to the aggregator server.
func (a *AggregatorReader) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// ReadCCVData returns the next available CCV data entries.
func (a *AggregatorReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	resp, err := a.messageDiscoveryClient.GetMessagesSince(ctx, &msgdiscoverypb.GetMessagesSinceRequest{
		SinceSequence: a.since.Load(),
	})
	if err != nil {
		return nil, fmt.Errorf("error calling GetMessagesSince: %w", err)
	}

	a.lggr.Debugw("Got messages since", "count", len(resp.Results), "since", a.since.Load())
	// Convert the response to []types.QueryResponse
	results := make([]protocol.QueryResponse, 0, len(resp.Results))
	tempSince := a.since.Load()
	for i, resultWithSeq := range resp.Results {
		if resultWithSeq.VerifierResult == nil {
			return nil, fmt.Errorf("nil VerifierResults at index %d", i)
		}

		result := v1.VerifierResult{VerifierResult: resultWithSeq.VerifierResult}
		verifierResult, err1 := result.ToVerifierResult()
		if err1 != nil {
			return nil, fmt.Errorf("error converting VerifierResults at index %d: %w", i, err1)
		}

		sequence := resultWithSeq.Sequence
		if sequence >= tempSince {
			tempSince = sequence + 1
		}

		results = append(results, protocol.QueryResponse{
			Timestamp: nil,
			Data:      verifierResult,
		})
	}

	a.since.Store(tempSince)

	return results, nil
}

func (a *AggregatorReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	messageIDsBytes := make([][]byte, 0, len(messageIDs))
	for _, id := range messageIDs {
		messageIDsBytes = append(messageIDsBytes, id[:])
	}

	protoResponse, err := a.client.GetVerifierResultsForMessage(ctx, &verifierpb.GetVerifierResultsForMessageRequest{
		MessageIds: messageIDsBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("error calling GetVerifierResultsForMessage: %w", err)
	}
	if protoResponse == nil {
		return nil, fmt.Errorf("GetVerifierResultsForMessage returned nil response")
	}

	resp := v1.VerifierResultsResponse{GetVerifierResultsForMessageResponse: protoResponse}
	return resp.ToVerifierResults()
}
