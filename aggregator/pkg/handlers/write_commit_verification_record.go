package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// AggregationTriggerer defines an interface for triggering aggregation checks.
type AggregationTriggerer interface {
	CheckAggregation(committeeID string, messageID model.MessageID) error
}

// WriteCommitVerificationRecordHandler handles requests to write commit verification records.
type WriteCommitVerificationRecordHandler struct {
	storage    common.CommitVerificationStore
	aggregator AggregationTriggerer
	logger     logger.Logger
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitVerificationRecordHandler) Handle(ctx context.Context, req *aggregator.WriteCommitVerificationRequest) (*aggregator.WriteCommitVerificationResponse, error) {
	h.logger.Infof("Received WriteCommitVerificationRequest: ParticipantID=%s, CommitteeID=%s, MessageID=%x",
		req.GetParticipantId(), req.GetCommitteeId(), req.GetCommitVerificationRecord().GetMessageId())
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

	if err := h.aggregator.CheckAggregation(req.GetCommitteeId(), req.GetCommitVerificationRecord().GetMessageId()); err != nil {
		return &aggregator.WriteCommitVerificationResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	return &aggregator.WriteCommitVerificationResponse{
		Status: aggregator.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitVerificationRecordHandler creates a new instance of WriteCommitVerificationRecordHandler.
func NewWriteCommitVerificationRecordHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, l logger.Logger) *WriteCommitVerificationRecordHandler {
	return &WriteCommitVerificationRecordHandler{
		storage:    store,
		aggregator: aggregator,
		logger:     l,
	}
}
