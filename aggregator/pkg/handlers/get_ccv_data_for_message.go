package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
)

type GetCCVDataForMessageHandler struct {
	storage common.CommitVerificationAggregatedStore
}

// Handle processes the get request and retrieves the commit verification data.
func (h *GetCCVDataForMessageHandler) Handle(ctx context.Context, req *aggregator.GetCCVDataForMessageRequest) (*aggregator.MessageWithCCVData, error) {
	data := h.storage.GetCCVData(ctx, req.MessageId)

	return &aggregator.MessageWithCCVData{
		Message: data.Verifications[0].Message,
		// TODO: Fill in the rest
	}, nil
}

// NewGetCCVDataForMessageHandler creates a new instance of GetCCVDataForMessageHandler.
func NewGetCCVDataForMessageHandler(storage common.CommitVerificationAggregatedStore) *GetCCVDataForMessageHandler {
	return &GetCCVDataForMessageHandler{
		storage: storage,
	}
}
