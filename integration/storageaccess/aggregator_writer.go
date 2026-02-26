package storageaccess

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	insecuregrpc "google.golang.org/grpc/credentials/insecure"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

const (
	AdapterMinTLSVersion = tls.VersionTLS12
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
}

// WriteCCVNodeData writes CCV data to the aggregator via gRPC and returns detailed per-request results.
func (a *AggregatorWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	a.lggr.Infow("Storing CCV data using aggregator ", "count", len(ccvDataList))

	results := make([]protocol.WriteResult, len(ccvDataList))

	// Pre-populate results with input data
	for i, ccvData := range ccvDataList {
		results[i] = protocol.WriteResult{
			Input:     ccvData,
			Status:    protocol.WriteFailure,
			Error:     nil,
			Retryable: true, // Aggregator errors are always retryable
		}
	}

	requests := make([]*committeepb.WriteCommitteeVerifierNodeResultRequest, 0, len(ccvDataList))
	for i, ccvData := range ccvDataList {
		req, err := mapCCVDataToCCVNodeDataProto(ccvData)
		if err != nil {
			results[i].Error = fmt.Errorf("failed to create proto request: %w", err)
			a.lggr.Errorw("Failed to map CCV data to proto", "messageID", ccvData.MessageID.String(), "error", err)
			// Continue processing other requests
			requests = append(requests, nil)
			continue
		}
		requests = append(requests, req)
	}

	responses, err := a.client.BatchWriteCommitteeVerifierNodeResult(
		ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
			Requests: requests,
		},
	)
	if err != nil {
		// If the entire gRPC call failed, mark all as failed (still retryable)
		batchErr := fmt.Errorf("error calling BatchWriteCommitteeVerifierNodeResult: %w", err)
		for i := range results {
			if results[i].Error == nil {
				results[i].Error = batchErr
			}
		}
		return results, batchErr
	}

	// Process individual responses
	for i, resp := range responses.Responses {
		if i >= len(ccvDataList) {
			continue
		}

		messageID := ccvDataList[i].MessageID.String()

		if resp.Status != committeepb.WriteStatus_SUCCESS {
			// Extract detailed error information from the Errors array if available
			var errorCode string
			var errorMessage string
			if i < len(responses.Errors) && responses.Errors[i] != nil {
				// Convert the int32 code to gRPC codes.Code for human-readable output
				errorCode = codes.Code(responses.Errors[i].GetCode()).String() //nolint:gosec // gRPC error codes are always non-negative.
				errorMessage = responses.Errors[i].GetMessage()
			}

			results[i].Status = protocol.WriteFailure
			results[i].Error = fmt.Errorf("write failed with status %s: code=%s, message=%s",
				resp.Status.String(), errorCode, errorMessage)
			results[i].Retryable = true // Always retryable for aggregator

			a.lggr.Errorw("BatchWriteCommitteeVerifierNodeResult failed",
				"status", resp.Status.String(),
				"messageID", messageID,
				"errorCode", errorCode,
				"errorMessage", errorMessage,
			)
		} else {
			results[i].Status = protocol.WriteSuccess
			results[i].Error = nil
			results[i].Retryable = false // Success, no retry needed
			a.lggr.Infow("Successfully stored CCV data", "messageID", messageID)
		}
	}

	return results, nil
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

func buildDialOptions(hmacConfig *hmac.ClientConfig, insecure bool, maxRecvMsgSizeBytes int) []grpc.DialOption {
	var opts []grpc.DialOption
	if insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecuregrpc.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: AdapterMinTLSVersion})))
	}

	if hmacConfig != nil {
		opts = append(opts, grpc.WithUnaryInterceptor(hmac.NewClientInterceptor(hmacConfig)))
	}

	if maxRecvMsgSizeBytes > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsgSizeBytes)))
	}

	return opts
}

// NewAggregatorWriter creates instance of AggregatorWriter that satisfies CCVNodeDataWriter interface.
// If insecure is true, TLS verification is disabled (only for testing).
func NewAggregatorWriter(address string, lggr logger.Logger, hmacConfig *hmac.ClientConfig, insecure bool) (*AggregatorWriter, error) {
	conn, err := grpc.NewClient(address, buildDialOptions(hmacConfig, insecure, 0)...)
	if err != nil {
		return nil, err
	}

	return &AggregatorWriter{
		client: committeepb.NewCommitteeVerifierClient(conn),
		conn:   conn,
		lggr:   lggr,
	}, nil
}
