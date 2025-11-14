package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type GetMessagesSinceHandler struct {
	storage   common.CommitVerificationAggregatedStore
	committee *model.Committee
	l         logger.SugaredLogger
	m         common.AggregatorMonitoring
}

func (h *GetMessagesSinceHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the get request and retrieves the commit verification data since the specified time.
func (h *GetMessagesSinceHandler) Handle(ctx context.Context, req *pb.GetMessagesSinceRequest) (*pb.GetMessagesSinceResponse, error) {
	h.logger(ctx).Tracef("Received GetMessagesSinceRequest, sinceSequence: %d, nextToken: %v", req.SinceSequence, req.NextToken)
	storage, err := h.storage.QueryAggregatedReports(ctx, req.SinceSequence, &req.NextToken)
	if err != nil {
		h.logger(ctx).Errorw("failed to query aggregated reports", "sinceSequence", req.SinceSequence, "error", err)
		return nil, err
	}

	records := make([]*pb.MessageWithVerifierResult, 0, len(storage.Reports))
	for _, report := range storage.Reports {
		ccvData, err := model.MapAggregatedReportToCCVDataProto(report, h.committee)
		if err != nil {
			h.logger(ctx).Errorw("failed to map aggregated report to proto", "messageID", report.MessageID, "error", err)
			return nil, err
		}
		messageWithResult := &pb.MessageWithVerifierResult{
			Message:                  ccvData.Message,
			SourceVerifierAddress:    ccvData.SourceVerifierAddress,
			DestVerifierAddress:      ccvData.DestVerifierAddress,
			CcvData:                  ccvData.CcvData,
			Timestamp:                ccvData.Timestamp,
			Sequence:                 ccvData.Sequence,
			ReceiptBlobsFromMajority: model.ReceiptBlobsToProto(report.WinningReceiptBlobs),
		}
		records = append(records, messageWithResult)
	}

	h.m.Metrics().RecordMessageSinceNumberOfRecordsReturned(ctx, len(records))
	h.logger(ctx).Tracef("Returning %d records for GetMessagesSinceRequest", len(records))

	for _, report := range storage.Reports {
		h.logger(ctx).Tracef("Report MessageID: %x, Sequence: %d, Verifications: %d", report.MessageID, report.Sequence, len(report.Verifications))
	}

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
func NewGetMessagesSinceHandler(storage common.CommitVerificationAggregatedStore, committee *model.Committee, l logger.SugaredLogger, m common.AggregatorMonitoring) *GetMessagesSinceHandler {
	return &GetMessagesSinceHandler{
		storage:   storage,
		committee: committee,
		l:         l,
		m:         m,
	}
}
