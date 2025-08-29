package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/interfaces"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

type AggregationTriggerer interface {
	CheckAggregation(committee_id string, messageID model.MessageID)
}

type WriteCommitVerificationRecordHandler struct {
	storage    interfaces.CommitVerificationStore
	aggregator AggregationTriggerer
}

func (h *WriteCommitVerificationRecordHandler) Handle(ctx context.Context, req *aggregator.WriteCommitVerificationRequest) (*aggregator.WriteCommitVerificationResponse, error) {
	record := model.CommitVerificationRecord{
		CommitVerificationRecord: *req.GetCommitVerificationRecord(),
		ParticipantID:            req.GetParticipantId(),
		CommitteeID:              req.GetCommitteeId(),
	}
	err := h.storage.SaveCommitVerification(ctx, &record)

	if err != nil {
		return &aggregator.WriteCommitVerificationResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	h.aggregator.CheckAggregation(req.GetCommitteeId(), req.GetCommitVerificationRecord().GetMessageId())

	return &aggregator.WriteCommitVerificationResponse{
		Status: aggregator.WriteStatus_SUCCESS,
	}, nil
}

func NewWriteCommitVerificationRecordHandler(store interfaces.CommitVerificationStore, aggregator AggregationTriggerer) *WriteCommitVerificationRecordHandler {
	return &WriteCommitVerificationRecordHandler{
		storage:    store,
		aggregator: aggregator,
	}
}
