package handlers

import (
	"context"
	"fmt"
	"math"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

type QueryAggregatedCommitRecordsHandler struct {
	storage common.CommitVerificationAggregatedStore
}

func (h *QueryAggregatedCommitRecordsHandler) Handle(ctx context.Context, req *aggregator.QueryAggregatedCommitRecordsRequest) (*aggregator.QueryAggregatedCommitRecordsResponse, error) {
	storage := h.storage.QueryAggregatedReports(ctx, req.Start, req.End)

	records := make([]*aggregator.CommitVerificationRecord, 0, len(storage))
	for _, report := range storage {
		records = append(records, &aggregator.CommitVerificationRecord{
			MessageId: report.MessageID,
			// TODO: Fill in the rest
		})
	}

	if len(records) > math.MaxUint32 {
		return nil, fmt.Errorf("number of records (%d) exceeds max allowed records", len(records))
	}

	return &aggregator.QueryAggregatedCommitRecordsResponse{
		Records: records,
		Total:   uint32(len(records)), //nolint:gosec // length is checked above
	}, nil
}

// NewQueryAggregatedCommitRecordsHandler initializes QueryAggregatedCommitRecordsHandler.
func NewQueryAggregatedCommitRecordsHandler(storage common.CommitVerificationAggregatedStore) *QueryAggregatedCommitRecordsHandler {
	return &QueryAggregatedCommitRecordsHandler{
		storage: storage,
	}
}
