package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// ReadChainStatusHandler handles ReadChainStatus gRPC requests.
type ReadChainStatusHandler struct {
	storage common.ChainStatusStorageInterface
	l       logger.SugaredLogger
}

// NewReadChainStatusHandler creates a new ReadChainStatusHandler.
func NewReadChainStatusHandler(storage common.ChainStatusStorageInterface, l logger.SugaredLogger) *ReadChainStatusHandler {
	return &ReadChainStatusHandler{
		storage: storage,
		l:       l,
	}
}

func (h *ReadChainStatusHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes a ReadChainStatus request.
func (h *ReadChainStatusHandler) Handle(ctx context.Context, req *pb.ReadChainStatusRequest) (*pb.ReadChainStatusResponse, error) {
	// Extract caller identity from context (set by authentication middleware)
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		// no identity should be rare and indicates middleware misconfig
		h.logger(ctx).Errorf("no caller identity in context")
		return nil, status.Error(codes.Unauthenticated, "no caller identity in context")
	}

	// Validate the request (minimal validation required for read)
	if req == nil {
		h.logger(ctx).Errorf("invalid request: nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	// Retrieve chain statuses using the effective caller ID (handles admin on-behalf-of automatically)
	chainStatusMap, err := h.storage.GetClientChainStatus(ctx, identity.EffectiveCallerID)
	if err != nil {
		h.logger(ctx).Errorw("failed to retrieve chain statuses", "clientID", identity.EffectiveCallerID, "error", err)
		return nil, status.Errorf(codes.Internal, "failed to retrieve chain statuses: %v", err)
	}

	// Convert storage format to protobuf chain statuses
	protoChainStatuses := make([]*pb.ChainStatus, 0, len(chainStatusMap))
	for chainSelector, chainStatus := range chainStatusMap {
		protoChainStatuses = append(protoChainStatuses, &pb.ChainStatus{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: chainStatus.FinalizedBlockHeight,
			Disabled:             chainStatus.Disabled,
		})
	}

	return &pb.ReadChainStatusResponse{
		Statuses: protoChainStatuses,
	}, nil
}
