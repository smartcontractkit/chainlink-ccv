package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// WriteBlockCheckpointHandler handles WriteBlockCheckpoint gRPC requests.
type WriteBlockCheckpointHandler struct {
	storage common.CheckpointStorageInterface
}

// NewWriteBlockCheckpointHandler creates a new WriteBlockCheckpointHandler.
func NewWriteBlockCheckpointHandler(storage common.CheckpointStorageInterface) *WriteBlockCheckpointHandler {
	return &WriteBlockCheckpointHandler{
		storage: storage,
	}
}

// Handle processes a WriteBlockCheckpoint request.
func (h *WriteBlockCheckpointHandler) Handle(ctx context.Context, req *pb.WriteBlockCheckpointRequest) (*pb.WriteBlockCheckpointResponse, error) {
	// Extract caller identity from context (set by authentication middleware)
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return &pb.WriteBlockCheckpointResponse{Status: pb.WriteStatus_FAILED}, status.Error(codes.Unauthenticated, "no caller identity in context")
	}

	// Validate the request
	if err := validateWriteBlockCheckpointRequest(req); err != nil {
		return &pb.WriteBlockCheckpointResponse{Status: pb.WriteStatus_FAILED}, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	// Convert protobuf checkpoints to storage format
	checkpointMap := make(map[uint64]uint64, len(req.Checkpoints))
	for _, checkpoint := range req.Checkpoints {
		checkpointMap[checkpoint.ChainSelector] = checkpoint.FinalizedBlockHeight
	}

	// Store checkpoints using the caller's identity
	if err := h.storage.StoreCheckpoints(ctx, identity.CallerID, checkpointMap); err != nil {
		return &pb.WriteBlockCheckpointResponse{Status: pb.WriteStatus_FAILED}, status.Errorf(codes.Internal, "failed to store checkpoints: %v", err)
	}

	return &pb.WriteBlockCheckpointResponse{Status: pb.WriteStatus_SUCCESS}, nil
}

// validateWriteBlockCheckpointRequest validates the WriteBlockCheckpoint request.
func validateWriteBlockCheckpointRequest(req *pb.WriteBlockCheckpointRequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if len(req.Checkpoints) == 0 {
		return status.Error(codes.InvalidArgument, "checkpoints cannot be empty")
	}

	// Validate each checkpoint
	for _, checkpoint := range req.Checkpoints {
		if checkpoint.ChainSelector == 0 {
			return status.Error(codes.InvalidArgument, "chain_selector must be positive")
		}
		if checkpoint.FinalizedBlockHeight == 0 {
			return status.Error(codes.InvalidArgument, "finalized_block_height must be positive")
		}
	}

	return nil
}
