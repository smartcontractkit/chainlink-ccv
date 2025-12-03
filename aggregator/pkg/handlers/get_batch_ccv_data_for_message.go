package handlers

import (
	"context"

	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ethcommon "github.com/ethereum/go-ethereum/common"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// GetBatchCCVDataForMessageHandler handles batch requests to retrieve commit verification data for multiple message IDs.
type GetBatchCCVDataForMessageHandler struct {
	storage               common.CommitVerificationAggregatedStore
	committee             *model.Committee
	l                     logger.SugaredLogger
	maxMessageIDsPerBatch int
}

func (h *GetBatchCCVDataForMessageHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the batch get request and retrieves commit verification data for multiple message IDs.
func (h *GetBatchCCVDataForMessageHandler) Handle(ctx context.Context, req *pb.GetVerifierResultsForMessageRequest) (*pb.GetVerifierResultsForMessageResponse, error) {
	reqLogger := h.logger(ctx)
	reqLogger.Infof("Received batch verifier result request for %d message IDs", len(req.GetMessageIds()))

	// Validate batch size limits
	if len(req.GetMessageIds()) == 0 {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "message_ids cannot be empty")
	}
	if len(req.GetMessageIds()) > h.maxMessageIDsPerBatch {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "too many message_ids: %d, maximum allowed: %d", len(req.GetMessageIds()), h.maxMessageIDsPerBatch)
	}

	// Convert proto message IDs to model.MessageID
	messageIDs := make([]model.MessageID, len(req.GetMessageIds()))
	for i, messageID := range req.GetMessageIds() {
		messageIDs[i] = messageID
	}

	// Call storage for efficient batch retrieval
	results, err := h.storage.GetBatchCCVData(ctx, messageIDs)
	if err != nil {
		reqLogger.Errorf("Failed to retrieve batch CCV data: %v", err)
		return nil, grpcstatus.Errorf(codes.Internal, "failed to retrieve batch data: %v", err)
	}

	// Prepare response with 1:1 correspondence between message IDs and errors
	response := &pb.GetVerifierResultsForMessageResponse{
		Results: make([]*pb.VerifierResult, len(req.GetMessageIds())),
		Errors:  NewBatchErrorArray(len(req.GetMessageIds())),
	}

	// Process each message ID in order to maintain index correspondence
	for i, messageID := range req.GetMessageIds() {
		messageIDHex := ethcommon.Bytes2Hex(messageID)

		if report, found := results[messageIDHex]; found {
			// Map aggregated report to proto
			ccvData, err := model.MapAggregatedReportToCCVDataProto(report, h.committee)
			if err != nil {
				reqLogger.Errorf("Failed to map aggregated report to proto for message ID %s: %v", messageIDHex, err)
				SetBatchError(response.Errors, i, codes.Internal, "failed to map aggregated report")
				continue
			}

			response.Results[i] = ccvData
			SetBatchSuccess(response.Errors, i)
		} else {
			SetBatchError(response.Errors, i, codes.NotFound, "message ID not found")
		}
	}

	reqLogger.Infof("Batch request completed, %d message IDs processed", len(req.GetMessageIds()))
	return response, nil
}

// NewGetBatchCCVDataForMessageHandler creates a new instance of GetBatchCCVDataForMessageHandler.
func NewGetBatchCCVDataForMessageHandler(storage common.CommitVerificationAggregatedStore, committee *model.Committee, maxMessageIDsPerBatch int, l logger.SugaredLogger) *GetBatchCCVDataForMessageHandler {
	return &GetBatchCCVDataForMessageHandler{
		storage:               storage,
		committee:             committee,
		l:                     l,
		maxMessageIDsPerBatch: maxMessageIDsPerBatch,
	}
}
