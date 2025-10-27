package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ReadChainStatusHandler handles ReadChainStatus gRPC requests.
type ReadChainStatusHandler struct {
	storage common.ChainStatusStorageInterface
}

// NewReadChainStatusHandler creates a new ReadChainStatusHandler.
func NewReadChainStatusHandler(storage common.ChainStatusStorageInterface) *ReadChainStatusHandler {
	return &ReadChainStatusHandler{
		storage: storage,
	}
}

// Handle processes a ReadChainStatus request.
func (h *ReadChainStatusHandler) Handle(ctx context.Context, req *pb.ReadChainStatusRequest) (*pb.ReadChainStatusResponse, error) {
	// Extract caller identity from context (set by authentication middleware)
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no caller identity in context")
	}

	// Validate the request (minimal validation required for read)
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	// Retrieve chain statuses for this client using their identity
	chainStatusMap, err := h.storage.GetClientChainStatus(ctx, identity.CallerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve chain statuses: %v", err)
	}

	// Convert storage format to protobuf chain statuses
	protoChainStatuses := make([]*pb.ChainStatus, 0, len(chainStatusMap))
	for chainSelector, blockHeight := range chainStatusMap {
		protoChainStatuses = append(protoChainStatuses, &pb.ChainStatus{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: blockHeight,
			Disabled:             false, // Stored chains are always enabled
		})
	}

	return &pb.ReadChainStatusResponse{
		Statuses: protoChainStatuses,
	}, nil
}
