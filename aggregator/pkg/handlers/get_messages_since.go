package handlers

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/middlewares"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type GetMessagesSinceHandler struct {
	storage                          common.CommitVerificationAggregatedStore
	committee                        map[string]*model.Committee
	maxAnonymousGetMessageSinceRange time.Duration
	l                                logger.SugaredLogger
	m                                common.AggregatorMonitoring
}

func (h *GetMessagesSinceHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the get request and retrieves the commit verification data since the specified time.
func (h *GetMessagesSinceHandler) Handle(ctx context.Context, req *pb.GetMessagesSinceRequest) (*pb.GetMessagesSinceResponse, error) {
	identity, ok := middlewares.IdentityFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no caller identity in context")
	}

	if identity.IsAnonymous && h.maxAnonymousGetMessageSinceRange > 0 {
		if time.Since(time.Unix(req.Since, 0)) > h.maxAnonymousGetMessageSinceRange {
			return nil, status.Error(codes.PermissionDenied, fmt.Sprintf("anonymous access is limited to data from the last %s", h.maxAnonymousGetMessageSinceRange.String()))
		}
	}

	committeeID := LoadCommitteeIDFromContext(ctx)

	h.logger(ctx).Tracef("Received GetMessagesSinceRequest")
	storage, err := h.storage.QueryAggregatedReports(ctx, req.Since, time.Now().Unix(), committeeID, &req.NextToken)
	if err != nil {
		return nil, err
	}

	records := make([]*pb.MessageWithCCVData, 0, len(storage.Reports))
	for _, report := range storage.Reports {
		ccvData, err := model.MapAggregatedReportToCCVDataProto(report, h.committee)
		if err != nil {
			return nil, err
		}
		records = append(records, ccvData)
	}

	h.m.Metrics().RecordMessageSinceNumberOfRecordsReturned(ctx, len(records))
	h.logger(ctx).Tracef("Returning %d records for GetMessagesSinceRequest", len(records))

	if storage.NextPageToken != nil {
		return &pb.GetMessagesSinceResponse{
			Results:   records,
			NextToken: *storage.NextPageToken,
		}, nil
	}

	return &pb.GetMessagesSinceResponse{
		Results: records,
	}, nil
}

// NewGetMessagesSinceHandler creates a new instance of GetMessagesSinceHandler.
func NewGetMessagesSinceHandler(storage common.CommitVerificationAggregatedStore, committee map[string]*model.Committee, l logger.SugaredLogger, m common.AggregatorMonitoring, maxAnonymousGetMessageSinceRange time.Duration) *GetMessagesSinceHandler {
	return &GetMessagesSinceHandler{
		storage:                          storage,
		committee:                        committee,
		l:                                l,
		m:                                m,
		maxAnonymousGetMessageSinceRange: maxAnonymousGetMessageSinceRange,
	}
}
