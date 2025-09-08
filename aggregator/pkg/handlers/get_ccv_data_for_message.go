package handlers

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GetCCVDataForMessageHandler struct {
	storage   common.CommitVerificationAggregatedStore
	committee map[string]*model.Committee
}

// Handle processes the get request and retrieves the commit verification data.
func (h *GetCCVDataForMessageHandler) Handle(ctx context.Context, req *aggregator.GetCCVDataForMessageRequest) (*aggregator.MessageWithCCVData, error) {
	data := h.storage.GetCCVData(ctx, req.MessageId)

	if data == nil {
		return nil, status.Errorf(codes.NotFound, "%s", fmt.Sprintf("no data found for message ID %x", req.MessageId))
	}

	ccvData, err := model.MapAggregatedReportToCCVDataProto(data, h.committee)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", fmt.Sprintf("failed to map aggregated report to CCV data: %v", err))
	}

	return ccvData, nil
}

// NewGetCCVDataForMessageHandler creates a new instance of GetCCVDataForMessageHandler.
func NewGetCCVDataForMessageHandler(storage common.CommitVerificationAggregatedStore, committee map[string]*model.Committee) *GetCCVDataForMessageHandler {
	return &GetCCVDataForMessageHandler{
		storage:   storage,
		committee: committee,
	}
}
