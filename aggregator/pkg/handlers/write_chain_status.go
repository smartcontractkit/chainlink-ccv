package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// WriteChainStatusHandler handles WriteChainStatus gRPC requests.
type WriteChainStatusHandler struct {
	storage common.ChainStatusStorageInterface
	l       logger.SugaredLogger
}

// NewWriteChainStatusHandler creates a new WriteChainStatusHandler.
func NewWriteChainStatusHandler(storage common.ChainStatusStorageInterface, l logger.SugaredLogger) *WriteChainStatusHandler {
	return &WriteChainStatusHandler{
		storage: storage,
		l:       l,
	}
}

func (h *WriteChainStatusHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes a WriteChainStatus request.
func (h *WriteChainStatusHandler) Handle(ctx context.Context, req *pb.WriteChainStatusRequest) (*pb.WriteChainStatusResponse, error) {
	// Extract caller identity from context (set by authentication middleware)
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		h.logger(ctx).Errorf("no caller identity in context")
		return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_FAILED}, status.Error(codes.Unauthenticated, "no caller identity in context")
	}

	// Validate the request
	if err := model.ValidateWriteChainStatusRequest(req); err != nil {
		h.logger(ctx).Errorw("invalid write chain status request", "clientID", identity.EffectiveCallerID, "error", err)
		return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_FAILED}, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	// Convert protobuf chain statuses to storage format
	chainStatusMap := make(map[uint64]*common.ChainStatus)
	for _, chainStatus := range req.Statuses {
		chainStatusMap[chainStatus.ChainSelector] = &common.ChainStatus{
			FinalizedBlockHeight: chainStatus.FinalizedBlockHeight,
			Disabled:             chainStatus.Disabled,
		}
	}

	// Store chain statuses using the effective caller ID (handles admin on-behalf-of automatically)
	if err := h.storage.StoreChainStatus(ctx, identity.EffectiveCallerID, chainStatusMap); err != nil {
		h.logger(ctx).Errorw("failed to store chain statuses", "clientID", identity.EffectiveCallerID, "error", err)
		return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_FAILED}, status.Errorf(codes.Internal, "failed to store chain statuses: %v", err)
	}

	return &pb.WriteChainStatusResponse{Status: pb.WriteStatus_SUCCESS}, nil
}
