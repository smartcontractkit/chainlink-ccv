package storageaccess

import (
	"context"
	"fmt"
	"sync/atomic"

	"google.golang.org/grpc"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

type AggregatorReader struct {
	client                 verifierpb.VerifierClient
	messageDiscoveryClient msgdiscoverypb.MessageDiscoveryClient
	lggr                   logger.Logger
	conn                   *grpc.ClientConn
	since                  atomic.Int64
}

// NewAggregatorReader creates instance of AggregatorReader that satisfies OffchainStorageReader interface.
// If insecure is true, TLS verification is disabled (only for testing).
// maxRecvMsgSizeBytes limits the maximum gRPC response size; 0 uses the gRPC default (4MB).
func NewAggregatorReader(address string, lggr logger.Logger, since int64, hmacConfig *hmac.ClientConfig, insecure bool, maxRecvMsgSizeBytes int) (*AggregatorReader, error) {
	conn, err := grpc.NewClient(address, buildDialOptions(hmacConfig, insecure, maxRecvMsgSizeBytes)...)
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
