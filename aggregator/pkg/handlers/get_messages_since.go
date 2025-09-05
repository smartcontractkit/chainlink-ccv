package handlers

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

type GetMessagesSinceHandler struct {
	storage common.CommitVerificationAggregatedStore
}

// Handle processes the get request and retrieves the commit verification data since the specified time.
func (h *GetMessagesSinceHandler) Handle(ctx context.Context, req *aggregator.GetMessagesSinceRequest) (*aggregator.GetMessagesSinceResponse, error) {
	storage := h.storage.QueryAggregatedReports(ctx, req.Since, time.Now().Unix())

	records := make([]*aggregator.CCVData, 0, len(storage))
	for _, report := range storage {
		records = append(records, &aggregator.CCVData{
			MessageId: report.MessageID,
			// TODO: Fill in the rest
		})
	}

	return &aggregator.GetMessagesSinceResponse{
		Results: records,
	}, nil
}

// NewGetMessagesSinceHandler creates a new instance of GetMessagesSinceHandler.
func NewGetMessagesSinceHandler(storage common.CommitVerificationAggregatedStore) *GetMessagesSinceHandler {
	return &GetMessagesSinceHandler{
		storage: storage,
	}
}
