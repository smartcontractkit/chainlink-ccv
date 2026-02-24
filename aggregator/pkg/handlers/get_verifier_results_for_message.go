package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// GetVerifierResultsForMessageHandler handles batch requests to retrieve commit verification data for multiple message IDs.
type GetVerifierResultsForMessageHandler struct {
	storage               common.CommitVerificationAggregatedStore
	committee             *model.Committee
	l                     logger.SugaredLogger
	maxMessageIDsPerBatch int
}

func (h *GetVerifierResultsForMessageHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the batch get request and retrieves commit verification data for multiple message IDs.
func (h *GetVerifierResultsForMessageHandler) Handle(ctx context.Context, req *verifierpb.GetVerifierResultsForMessageRequest) (*verifierpb.GetVerifierResultsForMessageResponse, error) {
	reqLogger := h.logger(ctx)

	// Validate batch size limits
	if len(req.GetMessageIds()) == 0 {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "message_ids cannot be empty")
	}
	if len(req.GetMessageIds()) > h.maxMessageIDsPerBatch {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "too many message_ids: %d, maximum allowed: %d", len(req.GetMessageIds()), h.maxMessageIDsPerBatch)
	}

	for i, id := range req.GetMessageIds() {
		if len(id) != protocol.MessageIDSize {
			return nil, grpcstatus.Errorf(codes.InvalidArgument, "message_ids[%d] must be exactly %d bytes, got %d", i, protocol.MessageIDSize, len(id))
		}
	}

	// Convert proto message IDs to model.MessageID
	messageIDs := make([]model.MessageID, len(req.GetMessageIds()))
	for i, messageID := range req.GetMessageIds() {
		messageIDs[i] = messageID
	}

	// Call storage for efficient batch retrieval
	results, err := h.storage.GetBatchAggregatedReportByMessageIDs(ctx, messageIDs)
	if err != nil {
		reqLogger.Errorw("Failed to retrieve batch CCV data", "error", err)
		return nil, grpcstatus.Error(codes.Internal, "failed to retrieve verification results")
	}

	// Prepare response with 1:1 correspondence between message IDs and errors
	response := &verifierpb.GetVerifierResultsForMessageResponse{
		Results: make([]*verifierpb.VerifierResult, len(req.GetMessageIds())),
		Errors:  NewBatchErrorArray(len(req.GetMessageIds())),
	}

	// Process each message ID in order to maintain index correspondence
	for i, messageID := range req.GetMessageIds() {
		messageIDHex := protocol.ByteSlice(messageID).String()

		if report, found := results[messageIDHex]; found {
			// Get quorum config and validate source verifier is in ccvAddresses
			quorumConfig, ok := h.committee.GetQuorumConfig(report.GetSourceChainSelector())
			if !ok {
				reqLogger.Errorf("Quorum config not found for source selector %d, message ID %s", report.GetSourceChainSelector(), messageIDHex)
				SetBatchError(response.Errors, i, codes.Internal, "internal error")
				continue
			}

			if !model.IsSourceVerifierInCCVAddresses(quorumConfig.GetSourceVerifierAddress(), report.GetMessageCCVAddresses()) {
				reqLogger.Debugf("Source verifier address not in ccvAddresses for message ID %s", messageIDHex)
				SetBatchError(response.Errors, i, codes.NotFound, "message ID not found")
				continue
			}

			// Map aggregated report to proto
			ccvData, err := model.MapAggregatedReportToVerifierResultProto(report, h.committee)
			if err != nil {
				reqLogger.Errorw("Failed to map aggregated report to proto", "messageID", messageIDHex, "error", err)
				SetBatchError(response.Errors, i, codes.Internal, "internal error")
				continue
			}

			response.Results[i] = ccvData
			SetBatchSuccess(response.Errors, i)
		} else {
			SetBatchError(response.Errors, i, codes.NotFound, "message ID not found")
		}
	}

	return response, nil
}

// NewGetVerifierResultsForMessageHandler creates a new instance of GetVerifierResultsForMessageHandler.
func NewGetVerifierResultsForMessageHandler(storage common.CommitVerificationAggregatedStore, committee *model.Committee, maxMessageIDsPerBatch int, l logger.SugaredLogger) *GetVerifierResultsForMessageHandler {
	return &GetVerifierResultsForMessageHandler{
		storage:               storage,
		committee:             committee,
		l:                     l,
		maxMessageIDsPerBatch: maxMessageIDsPerBatch,
	}
}
