package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

type GetCCVDataHandler struct {
	storage common.CommitVerificationAggregatedStore
}

// Handle processes the get request and retrieves the commit verification data.
func (h *GetCCVDataHandler) Handle(ctx context.Context, req *aggregator.GetCCVDataRequest) (*aggregator.CCVData, error) {
	data := h.storage.GetCCVData(ctx, req.MessageId)

	return &aggregator.CCVData{
		MessageId: data.MessageID,
		// TODO: Fill in the rest
	}, nil
}

// NewGetCCVDataHandler creates a new instance of GetCCVDataHandler.
func NewGetCCVDataHandler(storage common.CommitVerificationAggregatedStore) *GetCCVDataHandler {
	return &GetCCVDataHandler{
		storage: storage,
	}
}
