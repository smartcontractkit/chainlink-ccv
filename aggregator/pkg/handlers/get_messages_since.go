package handlers

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/pagination"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type GetMessagesSinceHandler struct {
	storage                common.CommitVerificationAggregatedStore
	committee              map[string]*model.Committee
	paginationTokenManager *pagination.PaginationTokenManager
	pageLimit              int
	l                      logger.SugaredLogger
	m                      common.AggregatorMonitoring
}

func (h *GetMessagesSinceHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the get request and retrieves the commit verification data since the specified time.
func (h *GetMessagesSinceHandler) Handle(ctx context.Context, req *pb.GetMessagesSinceRequest) (*pb.GetMessagesSinceResponse, error) {
	committeeID := LoadCommitteeIDFromContext(ctx)
	committeeIDStr := string(committeeID)

	h.logger(ctx).Tracef("Received GetMessagesSinceRequest with since=%d, nextToken=%s", req.Since, req.NextToken)

	// Parse pagination token if provided
	var lastSeqNum *int64
	if req.NextToken != "" {
		tokenPayload, err := h.paginationTokenManager.ValidateToken(req.NextToken, committeeIDStr)
		if err != nil {
			h.logger(ctx).Warnf("Invalid pagination token: %v", err)
			return nil, err
		}
		lastSeqNum = &tokenPayload.LastSeqNum
		h.logger(ctx).Tracef("Parsed pagination token: lastSeqNum=%d", *lastSeqNum)
	}

	// Query storage with pagination parameters
	paginatedResponse, err := h.storage.QueryAggregatedReports(ctx, req.Since, time.Now().Unix(), committeeIDStr, h.pageLimit, lastSeqNum)
	if err != nil {
		return nil, err
	}

	// Convert to proto messages
	records := make([]*pb.MessageWithCCVData, 0, len(paginatedResponse.Reports))
	for _, report := range paginatedResponse.Reports {
		ccvData, err := model.MapAggregatedReportToCCVDataProto(report, h.committee)
		if err != nil {
			return nil, err
		}
		records = append(records, ccvData)
	}

	// Generate next token if there are more results
	var nextToken string
	if paginatedResponse.HasMore && paginatedResponse.LastSeqNum != nil {
		nextToken, err = h.paginationTokenManager.GenerateToken(*paginatedResponse.LastSeqNum, committeeIDStr)
		if err != nil {
			h.logger(ctx).Errorf("Failed to generate pagination token: %v", err)
			return nil, err
		}
		h.logger(ctx).Tracef("Generated next token for lastSeqNum=%d", *paginatedResponse.LastSeqNum)
	}

	h.m.Metrics().RecordMessageSinceNumberOfRecordsReturned(ctx, len(records))
	h.logger(ctx).Tracef("Returning %d records for GetMessagesSinceRequest, hasMore=%t", len(records), paginatedResponse.HasMore)

	return &pb.GetMessagesSinceResponse{
		Results:   records,
		NextToken: nextToken,
	}, nil
}

// NewGetMessagesSinceHandler creates a new instance of GetMessagesSinceHandler.
func NewGetMessagesSinceHandler(storage common.CommitVerificationAggregatedStore, committee map[string]*model.Committee, tokenManager *pagination.PaginationTokenManager, pageLimit int, l logger.SugaredLogger, m common.AggregatorMonitoring) *GetMessagesSinceHandler {
	return &GetMessagesSinceHandler{
		storage:                storage,
		committee:              committee,
		paginationTokenManager: tokenManager,
		pageLimit:              pageLimit,
		l:                      l,
		m:                      m,
	}
}
