// Package handlers provides HTTP and gRPC request handlers for the aggregator service.
package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
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
			return &aggregator.ReadCommitCCVNodeDataResponse{}, err
		}
	}

	id := model.CommitVerificationRecordIdentifier{
		PublicKey: req.GetPublicKey(),
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
