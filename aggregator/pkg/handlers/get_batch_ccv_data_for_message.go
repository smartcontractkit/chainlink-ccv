package handlers

import (
	"context"

	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ethcommon "github.com/ethereum/go-ethereum/common"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
	grpcstatus "google.golang.org/grpc/status"
)

// GetBatchCCVDataForMessageHandler handles batch requests to retrieve commit verification data for multiple message IDs.
type GetBatchCCVDataForMessageHandler struct {
	storage               common.CommitVerificationAggregatedStore
	committee             map[string]*model.Committee
	l                     logger.SugaredLogger
	maxMessageIDsPerBatch int
}

func (h *GetBatchCCVDataForMessageHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the batch get request and retrieves commit verification data for multiple message IDs.
func (h *GetBatchCCVDataForMessageHandler) Handle(ctx context.Context, req *pb.BatchGetVerifierResultForMessageRequest) (*pb.BatchGetVerifierResultForMessageResponse, error) {
	committeeID := LoadCommitteeIDFromContext(ctx)
	ctx = scope.WithCommitteeID(ctx, committeeID)

	reqLogger := h.logger(ctx)
	reqLogger.Infof("Received batch verifier result request for %d requests", len(req.GetRequests()))

	// Validate batch size limits
	if len(req.GetRequests()) == 0 {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "requests cannot be empty")
	}
	if len(req.GetRequests()) > h.maxMessageIDsPerBatch {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "too many requests: %d, maximum allowed: %d", len(req.GetRequests()), h.maxMessageIDsPerBatch)
	}

	// Convert proto message IDs to model.MessageID and track original requests
	messageIDs := make([]model.MessageID, len(req.GetRequests()))
	originalRequests := make(map[string]*pb.GetVerifierResultForMessageRequest)
	for i, request := range req.GetRequests() {
		messageIDs[i] = request.GetMessageId()
		messageIDHex := ethcommon.Bytes2Hex(request.GetMessageId())
		originalRequests[messageIDHex] = request
	}

	// Call storage for efficient batch retrieval
	results, err := h.storage.GetBatchCCVData(ctx, messageIDs, committeeID)
	if err != nil {
		reqLogger.Errorf("Failed to retrieve batch CCV data: %v", err)
		return nil, grpcstatus.Errorf(codes.Internal, "failed to retrieve batch data: %v", err)
	}

	// Prepare response with 1:1 correspondence between requests and errors
	response := &pb.BatchGetVerifierResultForMessageResponse{
		Results: make([]*pb.VerifierResult, 0),
		Errors:  NewBatchErrorArray(len(req.GetRequests())),
	}

	// Process each request in order to maintain index correspondence
	for i, request := range req.GetRequests() {
		messageIDHex := ethcommon.Bytes2Hex(request.GetMessageId())

		if report, found := results[messageIDHex]; found {
			// Map aggregated report to proto
			ccvData, err := model.MapAggregatedReportToCCVDataProto(report, h.committee)
			if err != nil {
				reqLogger.Errorf("Failed to map aggregated report to proto for message ID %s: %v", messageIDHex, err)
				SetBatchError(response.Errors, i, codes.Internal, "failed to map aggregated report")
				continue
			}

			// Create VerifierResult
			verifierResult := &pb.VerifierResult{
				Message:               ccvData.Message,
				SourceVerifierAddress: ccvData.SourceVerifierAddress,
				DestVerifierAddress:   ccvData.DestVerifierAddress,
				CcvData:               ccvData.CcvData,
				Timestamp:             ccvData.Timestamp,
				Sequence:              ccvData.Sequence,
			}

			response.Results = append(response.Results, verifierResult)
			SetBatchSuccess(response.Errors, i)
		} else {
			SetBatchError(response.Errors, i, codes.NotFound, "message ID not found")
		}
	}

	reqLogger.Infof("Batch request completed: %d found, %d errors", len(response.Results), len(response.Errors))
	return response, nil
}

// NewGetBatchCCVDataForMessageHandler creates a new instance of GetBatchCCVDataForMessageHandler.
func NewGetBatchCCVDataForMessageHandler(storage common.CommitVerificationAggregatedStore, committee map[string]*model.Committee, maxMessageIDsPerBatch int, l logger.SugaredLogger) *GetBatchCCVDataForMessageHandler {
	return &GetBatchCCVDataForMessageHandler{
		storage:               storage,
		committee:             committee,
		l:                     l,
		maxMessageIDsPerBatch: maxMessageIDsPerBatch,
	}
}
