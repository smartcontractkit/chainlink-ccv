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

// WriteCommitCCVNodeDataHandler handles requests to write commit verification records.
type WriteCommitCCVNodeDataHandler struct {
	storage           common.CommitVerificationStore
	aggregator        AggregationTriggerer
	logger            logger.Logger
	disableValidation bool
}

// Handle processes the write request and saves the commit verification record.
func (h *WriteCommitCCVNodeDataHandler) Handle(ctx context.Context, req *aggregator.WriteCommitCCVNodeDataRequest) (*aggregator.WriteCommitCCVNodeDataResponse, error) {
	h.logger.Infof("Received WriteCommitCCVNodeDataRequest: MessageID=%x", req.CcvNodeData.GetMessageId())
	if !h.disableValidation {
		if err := validateWriteRequest(req); err != nil {
			return &aggregator.WriteCommitCCVNodeDataResponse{
				Status: aggregator.WriteStatus_FAILED,
			}, err
		}
	}

	record := model.CommitVerificationRecord{
		MessageWithCCVNodeData: *req.GetCcvNodeData(),
	}
	err := h.storage.SaveCommitVerification(ctx, &record)
	if err != nil {
		return &aggregator.WriteCommitCCVNodeDataResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	if err := h.aggregator.CheckAggregation(req.CcvNodeData.GetMessageId()); err != nil {
		return &aggregator.WriteCommitCCVNodeDataResponse{
			Status: aggregator.WriteStatus_FAILED,
		}, err
	}

	return &aggregator.WriteCommitCCVNodeDataResponse{
		Status: aggregator.WriteStatus_SUCCESS,
	}, nil
}

// NewWriteCommitCCVNodeDataHandler creates a new instance of WriteCommitCCVNodeDataHandler.
func NewWriteCommitCCVNodeDataHandler(store common.CommitVerificationStore, aggregator AggregationTriggerer, l logger.Logger, disableValidation bool) *WriteCommitCCVNodeDataHandler {
	return &WriteCommitCCVNodeDataHandler{
		storage:           store,
		aggregator:        aggregator,
		logger:            l,
		disableValidation: disableValidation,
	}
}
