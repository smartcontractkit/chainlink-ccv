package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// AggregationTriggerer defines an interface for triggering aggregation checks.
type AggregationTriggerer interface {
	CheckAggregation(messageID model.MessageID) error
}

// WriteCommitVerificationRecordHandler handles requests to write commit verification records.
type WriteCommitVerificationRecordHandler struct {
	storage           common.CommitVerificationStore
	aggregator        AggregationTriggerer
	logger            logger.Logger
	disableValidation bool
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitVerificationRecordHandler) Handle(ctx context.Context, req *aggregator.WriteCommitVerificationRequest) (*aggregator.WriteCommitVerificationResponse, error) {
	h.logger.Infof("Received WriteCommitVerificationRequest: MessageID=%x", req.GetCommitVerificationRecord().GetMessageId())
	if !h.disableValidation {
		if err := validateWriteRequest(req); err != nil {
			return &aggregator.WriteCommitVerificationResponse{
				Status: aggregator.WriteStatus_FAILED,
			}, err
		}
	}

	record := model.CommitVerificationRecord{
		CommitVerificationRecord: *req.GetCommitVerificationRecord(),
	}
	err := h.storage.SaveCommitVerification(ctx, &record)

	if err != nil {
		return &aggregator.WriteCommitVerificationResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	if err := h.aggregator.CheckAggregation(req.GetCommitVerificationRecord().GetMessageId()); err != nil {
		return &aggregator.WriteCommitVerificationResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	return &aggregator.WriteCommitVerificationResponse{
		Status: aggregator.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitVerificationRecordHandler creates a new instance of WriteCommitVerificationRecordHandler.
func NewWriteCommitVerificationRecordHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, l logger.Logger, disableValidation bool) *WriteCommitVerificationRecordHandler {
	return &WriteCommitVerificationRecordHandler{
		storage:           store,
		aggregator:        aggregator,
		logger:            l,
		disableValidation: disableValidation,
	}
}
