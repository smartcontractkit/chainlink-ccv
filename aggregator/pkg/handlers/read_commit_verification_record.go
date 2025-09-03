// Package handlers provides HTTP and gRPC request handlers for the aggregator service.
package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// ReadCommitVerificationRecordHandler handles requests to read commit verification records.
type ReadCommitVerificationRecordHandler struct {
	storage           common.CommitVerificationStore
	disableValidation bool
}

// Handle processes the read request and retrieves the corresponding commit verification record.
func (h *ReadCommitVerificationRecordHandler) Handle(ctx context.Context, req *aggregator.ReadCommitVerificationRequest) (*aggregator.ReadCommitVerificationResponse, error) {
	if !h.disableValidation {
		if err := validateReadRequest(req); err != nil {
			return &aggregator.ReadCommitVerificationResponse{}, err
		}
	}

	id := model.CommitVerificationRecordIdentifier{
		ParticipantID: req.GetParticipantId(),
		CommitteeID:   req.GetCommitteeId(),
		MessageID:     req.GetMessageId(),
	}

	record, err := h.storage.GetCommitVerification(ctx, id)
	if err != nil {
		return nil, err
	}

	return &aggregator.ReadCommitVerificationResponse{
		CommitVerificationRecord: &record.CommitVerificationRecord,
	}, nil
}

// NewReadCommitVerificationRecordHandler creates a new instance of ReadCommitVerificationRecordHandler.
func NewReadCommitVerificationRecordHandler(store common.CommitVerificationStore, disableValidation bool) *ReadCommitVerificationRecordHandler {
	return &ReadCommitVerificationRecordHandler{
		storage:           store,
		disableValidation: disableValidation,
	}
}
