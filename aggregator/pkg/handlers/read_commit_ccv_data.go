// Package handlers provides HTTP and gRPC request handlers for the aggregator service.
package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReadCommitCCVNodeDataHandler handles requests to read commit verification records.
type ReadCommitCCVNodeDataHandler struct {
	storage           common.CommitVerificationStore
	disableValidation bool
}

// Handle processes the read request and retrieves the corresponding commit verification record.
func (h *ReadCommitCCVNodeDataHandler) Handle(ctx context.Context, req *aggregator.ReadCommitCCVNodeDataRequest) (*aggregator.ReadCommitCCVNodeDataResponse, error) {
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
func NewReadCommitCCVNodeDataHandler(store common.CommitVerificationStore, disableValidation bool) *ReadCommitCCVNodeDataHandler {
	return &ReadCommitCCVNodeDataHandler{
		storage:           store,
		disableValidation: disableValidation,
	}
}
