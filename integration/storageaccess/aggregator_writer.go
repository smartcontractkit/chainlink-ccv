package storageaccess

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	insecuregrpc "google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

const (
	AdapterMinTLSVersion = tls.VersionTLS12
	// DefaultMaxMessageSize is the default gRPC max message size (4MB).
	DefaultMaxMessageSize = 4 * 1024 * 1024
	// ProtoBatchOverhead is an estimate for proto encoding overhead for the batch wrapper
	// This accounts for field tags, length prefixes, and the response structure.
	ProtoBatchOverhead = 1024
)

// requestWithSize holds a proto request along with its size and original index.
type requestWithSize struct {
	req     *committeepb.WriteCommitteeVerifierNodeResultRequest
	size    int
	origIdx int
	ccvData protocol.VerifierNodeResult
}

type AggregatorWriter struct {
	client         committeepb.CommitteeVerifierClient
	conn           *grpc.ClientConn
	lggr           logger.Logger
	maxMessageSize int
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
// It automatically splits batches that would exceed the gRPC max message size limit.
func (a *AggregatorWriter) WriteCCVNodeData(ctx context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	a.lggr.Infow("Storing CCV data using aggregator", "count", len(ccvDataList))

	results := make([]protocol.WriteResult, len(ccvDataList))

	// Pre-populate results with input data
	for i, ccvData := range ccvDataList {
		results[i] = protocol.WriteResult{
			Input:     ccvData,
			Status:    protocol.WriteFailure,
			Error:     nil,
			Retryable: true, // Aggregator errors are always retryable by default
		}
	}

	// Convert to proto and calculate sizes
	requestsWithSizes := make([]requestWithSize, 0, len(ccvDataList))
	for i, ccvData := range ccvDataList {
		req, err := mapCCVDataToCCVNodeDataProto(ccvData)
		if err != nil {
			results[i].Error = fmt.Errorf("failed to create proto request: %w", err)
			results[i].Retryable = false // Mapping errors are not retryable
			a.lggr.Errorw("Failed to map CCV data to proto", "messageID", ccvData.MessageID.String(), "error", err)
			continue
		}

		size := proto.Size(req)

		// Check if individual message exceeds max size
		if size+ProtoBatchOverhead > a.maxMessageSize {
			results[i].Error = fmt.Errorf("message size %d bytes exceeds max message size %d bytes", size, a.maxMessageSize)
			results[i].Status = protocol.WriteFailure
			results[i].Retryable = false // Too large messages are never retryable
			a.lggr.Errorw("Message exceeds max size limit",
				"messageID", ccvData.MessageID.String(),
				"messageSize", size,
				"maxSize", a.maxMessageSize)
			continue
		}

		requestsWithSizes = append(requestsWithSizes, requestWithSize{
			req:     req,
			size:    size,
			origIdx: i,
			ccvData: ccvData,
		})
	}

	if len(requestsWithSizes) == 0 {
		// All requests failed during mapping or size check
		return results, nil
	}

	// Split into batches based on byte size
	batches := a.splitIntoBatches(requestsWithSizes)

	a.lggr.Infow("Split requests into batches",
		"totalRequests", len(requestsWithSizes),
		"numBatches", len(batches))

	// Send each batch
	for batchIdx, batch := range batches {
		a.lggr.Debugw("Sending batch",
			"batchIndex", batchIdx,
			"batchSize", len(batch),
			"totalBatches", len(batches))

		if err := a.sendBatch(ctx, batch, results); err != nil {
			a.lggr.Errorw("Failed to send batch",
				"batchIndex", batchIdx,
				"error", err)
			// Continue with other batches even if one fails
		}
	}

	return results, nil
}

// splitIntoBatches splits requests into batches that don't exceed maxMessageSize.
func (a *AggregatorWriter) splitIntoBatches(requests []requestWithSize) [][]requestWithSize {
	if len(requests) == 0 {
		return nil
	}

	batches := make([][]requestWithSize, 0)
	currentBatch := make([]requestWithSize, 0)
	currentSize := ProtoBatchOverhead

	for _, req := range requests {
		// Check if adding this request would exceed the limit
		newSize := currentSize + req.size
		if newSize > a.maxMessageSize && len(currentBatch) > 0 {
			// Start a new batch
			batches = append(batches, currentBatch)
			currentBatch = make([]requestWithSize, 0)
			currentSize = ProtoBatchOverhead
		}

		currentBatch = append(currentBatch, req)
		currentSize += req.size
	}

	// Add the last batch
	if len(currentBatch) > 0 {
		batches = append(batches, currentBatch)
	}

	return batches
}

// sendBatch sends a single batch to the aggregator and updates results.
func (a *AggregatorWriter) sendBatch(ctx context.Context, batch []requestWithSize, results []protocol.WriteResult) error {
	requests := make([]*committeepb.WriteCommitteeVerifierNodeResultRequest, len(batch))
	for i, item := range batch {
		requests[i] = item.req
	}

	responses, err := a.client.BatchWriteCommitteeVerifierNodeResult(
		ctx, &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
			Requests: requests,
		},
	)
	if err != nil {
		// If the entire gRPC call failed, mark all in this batch as failed (still retryable)
		batchErr := fmt.Errorf("error calling BatchWriteCommitteeVerifierNodeResult: %w", err)
		for _, item := range batch {
			if results[item.origIdx].Error == nil {
				results[item.origIdx].Error = batchErr
				results[item.origIdx].Status = protocol.WriteFailure
				results[item.origIdx].Retryable = true
			}
		}
		return batchErr
	}

	// Process individual responses
	for i, resp := range responses.Responses {
		if i >= len(batch) {
			continue
		}

		item := batch[i]
		messageID := item.ccvData.MessageID.String()

		if resp.Status != committeepb.WriteStatus_SUCCESS {
			// Extract detailed error information from the Errors array if available
			var errorCode string
			var errorMessage string
			if i < len(responses.Errors) && responses.Errors[i] != nil {
				// Convert the int32 code to gRPC codes.Code for human-readable output
				errorCode = codes.Code(responses.Errors[i].GetCode()).String() //nolint:gosec // gRPC error codes are always non-negative.
				errorMessage = responses.Errors[i].GetMessage()
			}

			results[item.origIdx].Status = protocol.WriteFailure
			results[item.origIdx].Error = fmt.Errorf("write failed with status %s: code=%s, message=%s",
				resp.Status.String(), errorCode, errorMessage)
			results[item.origIdx].Retryable = true // Always retryable for aggregator

			a.lggr.Errorw("BatchWriteCommitteeVerifierNodeResult failed",
				"status", resp.Status.String(),
				"messageID", messageID,
				"errorCode", errorCode,
				"errorMessage", errorMessage,
			)
		} else {
			results[item.origIdx].Status = protocol.WriteSuccess
			results[item.origIdx].Error = nil
			results[item.origIdx].Retryable = false // Success, no retry needed
			a.lggr.Infow("Successfully stored CCV data", "messageID", messageID)
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
// maxRecvMsgSizeBytes sets the maximum gRPC message size; if 0, uses DefaultMaxMessageSize.
func NewAggregatorWriter(address string, lggr logger.Logger, hmacConfig *hmac.ClientConfig, insecure bool, maxRecvMsgSizeBytes int) (*AggregatorWriter, error) {
	if maxRecvMsgSizeBytes <= 0 {
		maxRecvMsgSizeBytes = DefaultMaxMessageSize
	}

	conn, err := grpc.NewClient(address, buildDialOptions(hmacConfig, insecure, maxRecvMsgSizeBytes)...)
	if err != nil {
		return nil, err
	}

	return &AggregatorWriter{
		client:         committeepb.NewCommitteeVerifierClient(conn),
		conn:           conn,
		lggr:           lggr,
		maxMessageSize: maxRecvMsgSizeBytes,
	}, nil
}
