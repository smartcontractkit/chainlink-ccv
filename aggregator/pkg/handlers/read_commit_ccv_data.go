// Package handlers provides HTTP and gRPC request handlers for the aggregator service.
package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

// ReadCommitCCVDataHandler handles requests to read commit verification records.
type ReadCommitCCVDataHandler struct {
	storage           common.CommitVerificationStore
	disableValidation bool
}

// Handle processes the read request and retrieves the corresponding commit verification record.
func (h *ReadCommitCCVDataHandler) Handle(ctx context.Context, req *aggregator.ReadCommitCCVDataRequest) (*aggregator.ReadCommitCCVDataResponse, error) {
	if !h.disableValidation {
		if err := validateReadRequest(req); err != nil {
			return &aggregator.ReadCommitCCVDataResponse{}, err
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

	return &aggregator.ReadCommitCCVDataResponse{
		CcvData: &record.CCVData,
	}, nil
}

// NewReadCommitCCVDataHandler creates a new instance of ReadCommitCCVDataHandler.
func NewReadCommitCCVDataHandler(store common.CommitVerificationStore, disableValidation bool) *ReadCommitCCVDataHandler {
	return &ReadCommitCCVDataHandler{
		storage:           store,
		disableValidation: disableValidation,
	}
}
