package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/interfaces"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type ReadCommitVerificationRecordHandler struct {
	storage interfaces.CommitVerificationStore
}

func (h *ReadCommitVerificationRecordHandler) Handle(ctx context.Context, req *aggregator.ReadCommitVerificationRequest) (*aggregator.ReadCommitVerificationResponse, error) {
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

func NewReadCommitVerificationRecordHandler(store interfaces.CommitVerificationStore) *ReadCommitVerificationRecordHandler {
	return &ReadCommitVerificationRecordHandler{
		storage: store,
	}
}
