package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// WriteChainStatusHandler handles WriteChainStatus gRPC requests.
type WriteChainStatusHandler struct {
	storage common.ChainStatusStorageInterface
}

// NewWriteChainStatusHandler creates a new WriteChainStatusHandler.
func NewWriteChainStatusHandler(storage common.ChainStatusStorageInterface) *WriteChainStatusHandler {
	return &WriteChainStatusHandler{
		storage: storage,
	}
}

// Handle processes a WriteChainStatus request.
func (h *WriteChainStatusHandler) Handle(ctx context.Context, req *pb.WriteChainStatusRequest) (*pb.WriteChainStatusResponse, error) {
	// Extract caller identity from context (set by authentication middleware)
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_FAILED}, status.Error(codes.Unauthenticated, "no caller identity in context")
	}

	// Validate the request
	if err := model.ValidateWriteChainStatusRequest(req); err != nil {
		return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_FAILED}, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	// Convert protobuf chain statuses to storage format (excluding disabled chains)
	chainStatusMap := make(map[uint64]uint64)
	for _, chainStatus := range req.Statuses {
		if !chainStatus.Disabled {
			chainStatusMap[chainStatus.ChainSelector] = chainStatus.FinalizedBlockHeight
		}
	}

	// Store chain statuses using the caller's identity
	if err := h.storage.StoreChainStatus(ctx, identity.CallerID, chainStatusMap); err != nil {
		return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_FAILED}, status.Errorf(codes.Internal, "failed to store chain statuses: %v", err)
	}

	return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_SUCCESS}, nil
}
