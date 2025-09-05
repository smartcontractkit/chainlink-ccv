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
	// CheckAggregation triggers the aggregation process for the specified message ID.
	CheckAggregation(messageID model.MessageID) error
}

// WriteCommitCCVDataHandler handles requests to write commit verification records.
type WriteCommitCCVDataHandler struct {
	storage           common.CommitVerificationStore
	aggregator        AggregationTriggerer
	logger            logger.Logger
	disableValidation bool
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitCCVDataHandler) Handle(ctx context.Context, req *aggregator.WriteCommitCCVDataRequest) (*aggregator.WriteCommitCCVDataResponse, error) {
	h.logger.Infof("Received WriteCommitCCVDataRequest: MessageID=%x", req.CcvData.GetMessageId())
	if !h.disableValidation {
		if err := validateWriteRequest(req); err != nil {
			return &aggregator.WriteCommitCCVDataResponse{
				Status: aggregator.WriteStatus_FAILED,
			}, err
		}
	}

	record := model.CommitVerificationRecord{
		CCVData: *req.GetCcvData(),
	}
	err := h.storage.SaveCommitVerification(ctx, &record)
	if err != nil {
		return &aggregator.WriteCommitCCVDataResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	if err := h.aggregator.CheckAggregation(req.CcvData.GetMessageId()); err != nil {
		return &aggregator.WriteCommitCCVDataResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	return &aggregator.WriteCommitCCVDataResponse{
		Status: aggregator.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitCCVDataHandler creates a new instance of WriteCommitCCVDataHandler.
func NewWriteCommitCCVDataHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, l logger.Logger, disableValidation bool) *WriteCommitCCVDataHandler {
	return &WriteCommitCCVDataHandler{
		storage:           store,
		aggregator:        aggregator,
		logger:            l,
		disableValidation: disableValidation,
	}
}
