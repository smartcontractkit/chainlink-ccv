package handler

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/storage"
)

type VerifierResultsHandler struct {
	lggr                  logger.Logger
	storage               storage.OffchainStorage
	maxMessageIDsPerBatch int
}

func NewVerifierResultsHandler(
	lggr logger.Logger,
	storage storage.OffchainStorage,
) *VerifierResultsHandler {
	return &VerifierResultsHandler{
		lggr:                  lggr,
		storage:               storage,
		maxMessageIDsPerBatch: 20,
	}
}

func (h *VerifierResultsHandler) Handle(ctx context.Context, req *pb.GetVerifierResultsForMessageRequest) (*pb.GetVerifierResultsForMessageResponse, error) {
	// Validate batch size limits
	if len(req.GetMessageIds()) == 0 {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "message_ids cannot be empty")
	}
	if len(req.GetMessageIds()) > h.maxMessageIDsPerBatch {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "too many message_ids: %d, maximum allowed: %d", len(req.GetMessageIds()), h.maxMessageIDsPerBatch)
	}

	messageIDs := make([]protocol.Bytes32, len(req.GetMessageIds()))
	for i, messageID := range req.GetMessageIds() {
		messageIDs[i] = protocol.Bytes32(messageID)
	}

	// Call storage for efficient batch retrieval
	results, err := h.storage.ReadBatchCCVData(ctx, messageIDs)
	if err != nil {
		h.lggr.Errorf("Failed to retrieve batch CCV data: %v", err)
		return nil, grpcstatus.Errorf(codes.Internal, "failed to retrieve batch data: %v", err)
	}

	// Process each message ID in order to maintain index correspondence
	pbResults := make([]*pb.VerifierResult, len(req.GetMessageIds()))
	for i, messageID := range messageIDs {
		result, ok := results[messageID]
		if !ok {
			// handle error for missing data
			return nil, fmt.Errorf("error")
		}

		pbResults[i] = &pb.VerifierResult{
			Message:                common.MapProtocolMessageToProtoMessage(&result.Data.Message),
			MessageCcvAddresses:    nil,
			MessageExecutorAddress: nil,
			CcvData:                result.Data.CCVData,
			Metadata:               nil,
		}
	}

	return &pb.GetVerifierResultsForMessageResponse{
		Results: pbResults,
		Errors:  nil,
	}, nil
}
