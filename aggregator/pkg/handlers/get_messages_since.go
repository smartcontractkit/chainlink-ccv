package handlers

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type GetMessagesSinceHandler struct {
	storage   common.CommitVerificationAggregatedStore
	committee map[string]*model.Committee
	l         logger.SugaredLogger
	m         common.AggregatorMonitoring
}

func (h *GetMessagesSinceHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the get request and retrieves the commit verification data since the specified time.
func (h *GetMessagesSinceHandler) Handle(ctx context.Context, req *aggregator.GetMessagesSinceRequest) (*aggregator.GetMessagesSinceResponse, error) {
	committeeID := LoadCommitteeIDFromContext(ctx)

	storage, err := h.storage.QueryAggregatedReports(ctx, req.Since, time.Now().Unix(), committeeID)
	if err != nil {
		h.logger(ctx).Errorw("failed to query aggregated reports", "error", err, "committeeID", committeeID, "since", req.Since)
		return nil, err
	}

	records := make([]*aggregator.MessageWithCCVData, 0, len(storage))
	for _, report := range storage {
		ccvData, err := model.MapAggregatedReportToCCVDataProto(report, h.committee)
		if err != nil {
			return nil, err
		}
		records = append(records, ccvData)
	}

	h.m.Metrics().RecordMessageSinceNumberOfRecordsReturned(ctx, len(records))

	return &aggregator.GetMessagesSinceResponse{
		Results: records,
	}, nil
}

// NewGetMessagesSinceHandler creates a new instance of GetMessagesSinceHandler.
func NewGetMessagesSinceHandler(storage common.CommitVerificationAggregatedStore, committee map[string]*model.Committee, l logger.SugaredLogger, m common.AggregatorMonitoring) *GetMessagesSinceHandler {
	return &GetMessagesSinceHandler{
		storage:   storage,
		committee: committee,
		l:         l,
		m:         m,
	}
}
