package handlers

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

type GetMessagesSinceHandler struct {
	storage   common.CommitVerificationAggregatedStore
	committee map[string]*model.Committee
}

// Handle processes the get request and retrieves the commit verification data since the specified time.
func (h *GetMessagesSinceHandler) Handle(ctx context.Context, req *aggregator.GetMessagesSinceRequest) (*aggregator.GetMessagesSinceResponse, error) {
	storage := h.storage.QueryAggregatedReports(ctx, req.Since, time.Now().Unix())

	records := make([]*aggregator.MessageWithCCVData, 0, len(storage))
	for _, report := range storage {
		ccvData, err := model.MapAggregatedReportToCCVDataProto(report, h.committee)
		if err != nil {
			return nil, err
		}
		records = append(records, ccvData)
	}

	return &aggregator.GetMessagesSinceResponse{
		Results: records,
	}, nil
}

// NewGetMessagesSinceHandler creates a new instance of GetMessagesSinceHandler.
func NewGetMessagesSinceHandler(storage common.CommitVerificationAggregatedStore, committee map[string]*model.Committee) *GetMessagesSinceHandler {
	return &GetMessagesSinceHandler{
		storage:   storage,
		committee: committee,
	}
}
