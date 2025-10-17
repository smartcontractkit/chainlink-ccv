package handlers

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type GetCCVDataForMessageHandler struct {
	storage   common.CommitVerificationAggregatedStore
	committee map[string]*model.Committee
	l         logger.SugaredLogger
}

func (h *GetCCVDataForMessageHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the get request and retrieves the commit verification data.
func (h *GetCCVDataForMessageHandler) Handle(ctx context.Context, req *pb.GetVerifierResultForMessageRequest) (*pb.VerifierResult, error) {
	committeeID := LoadCommitteeIDFromContext(ctx)
	ctx = scope.WithMessageID(ctx, req.MessageId)
	ctx = scope.WithCommitteeID(ctx, committeeID)
	h.logger(ctx).Infof("Received GetVerifierResultForMessageRequest")

	data, err := h.storage.GetCCVData(ctx, req.MessageId, committeeID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", fmt.Sprintf("failed to get CCV data for message ID %x: %v", req.MessageId, err))
	}

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
func NewGetCCVDataForMessageHandler(storage common.CommitVerificationAggregatedStore, committee map[string]*model.Committee, l logger.SugaredLogger) *GetCCVDataForMessageHandler {
	return &GetCCVDataForMessageHandler{
		storage:   storage,
		committee: committee,
		l:         l,
	}
}
