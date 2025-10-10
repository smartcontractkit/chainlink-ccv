package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/middlewares"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ReadBlockCheckpointHandler handles ReadBlockCheckpoint gRPC requests.
type ReadBlockCheckpointHandler struct {
	storage common.CheckpointStorageInterface
}

// NewReadBlockCheckpointHandler creates a new ReadBlockCheckpointHandler.
func NewReadBlockCheckpointHandler(storage common.CheckpointStorageInterface) *ReadBlockCheckpointHandler {
	return &ReadBlockCheckpointHandler{
		storage: storage,
	}
}

// Handle processes a ReadBlockCheckpoint request.
func (h *ReadBlockCheckpointHandler) Handle(ctx context.Context, req *pb.ReadBlockCheckpointRequest) (*pb.ReadBlockCheckpointResponse, error) {
	// Extract caller identity from context (set by authentication middleware)
	identity, ok := middlewares.IdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no caller identity in context")
	}

	// Validate the request (minimal validation required for read)
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	// Retrieve checkpoints for this client using their identity
	checkpointMap, err := h.storage.GetClientCheckpoints(ctx, identity.CallerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve checkpoints: %v", err)
	}

	// Convert storage format to protobuf checkpoints
	protoCheckpoints := make([]*pb.BlockCheckpoint, 0, len(checkpointMap))
	for chainSelector, blockHeight := range checkpointMap {
		protoCheckpoints = append(protoCheckpoints, &pb.BlockCheckpoint{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: blockHeight,
		})
	}

	return &pb.ReadBlockCheckpointResponse{
		Checkpoints: protoCheckpoints,
	}, nil
}
