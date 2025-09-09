// Package handlers provides HTTP and gRPC request handlers for the aggregator service.
package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ReadCommitCCVNodeDataHandler handles requests to read commit verification records.
type ReadCommitCCVNodeDataHandler struct {
	storage           common.CommitVerificationStore
	l                 logger.SugaredLogger
	disableValidation bool
}

func (h *ReadCommitCCVNodeDataHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the read request and retrieves the corresponding commit verification record.
func (h *ReadCommitCCVNodeDataHandler) Handle(ctx context.Context, req *aggregator.ReadCommitCCVNodeDataRequest) (*aggregator.ReadCommitCCVNodeDataResponse, error) {
	ctx = scope.WithMessageID(ctx, req.GetMessageId())
	h.logger(ctx).Infof("Received ReadCommitCCVNodeDataRequest")
	if !h.disableValidation {
		if err := validateReadRequest(req); err != nil {
			return &aggregator.ReadCommitCCVNodeDataResponse{}, status.Errorf(codes.InvalidArgument, "validation error: %v", err)
		}
	}

	id := model.CommitVerificationRecordIdentifier{
		Address:   req.GetAddress(),
		MessageID: req.GetMessageId(),
	}

	record, err := h.storage.GetCommitVerification(ctx, id)
	if err != nil {
		return nil, err
	}

	return &aggregator.ReadCommitCCVNodeDataResponse{
		CcvNodeData: &record.MessageWithCCVNodeData,
	}, nil
}

// NewReadCommitCCVNodeDataHandler creates a new instance of ReadCommitCCVNodeDataHandler.
func NewReadCommitCCVNodeDataHandler(store common.CommitVerificationStore, disableValidation bool, l logger.SugaredLogger) *ReadCommitCCVNodeDataHandler {
	return &ReadCommitCCVNodeDataHandler{
		storage:           store,
		disableValidation: disableValidation,
		l:                 l,
	}
}
