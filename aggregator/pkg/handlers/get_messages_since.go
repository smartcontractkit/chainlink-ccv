package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
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
func (h *GetMessagesSinceHandler) Handle(ctx context.Context, req *msgdiscoverypb.GetMessagesSinceRequest) (*msgdiscoverypb.GetMessagesSinceResponse, error) {
	h.logger(ctx).Tracef("Received GetMessagesSinceRequest, sinceSequence: %d", req.SinceSequence)
	batch, err := h.storage.QueryAggregatedReports(ctx, req.SinceSequence)
	if err != nil {
		h.logger(ctx).Errorw("failed to query aggregated reports", "sinceSequence", req.SinceSequence, "error", err)
		return nil, status.Error(codes.Internal, "failed to retrieve messages")
	}

	records := make([]*msgdiscoverypb.VerifierResultWithSequence, 0, len(batch.Reports))
	for _, report := range batch.Reports {
		verifierResult, err := model.MapAggregatedReportToVerifierResultProto(report, h.committee)
		if err != nil {
			h.logger(ctx).Errorw("failed to map aggregated report to proto", "messageID", report.MessageID, "error", err)
			return nil, status.Error(codes.Internal, "failed to process messages")
		}

		// If source verifier is not in ccvAddresses, nil out metadata addresses
		quorumConfig, ok := h.committee.GetQuorumConfig(report.GetSourceChainSelector())
		if !ok {
			h.logger(ctx).Errorw("missing quorum config for source chain selector", "sourceChainSelector", report.GetSourceChainSelector(), "messageID", report.MessageID)
			verifierResult.Metadata.VerifierSourceAddress = nil
			verifierResult.Metadata.VerifierDestAddress = nil
		} else if !model.IsSourceVerifierInCCVAddresses(quorumConfig.GetSourceVerifierAddressBytes(), report.GetMessageCCVAddresses()) {
			verifierResult.Metadata.VerifierSourceAddress = nil
			verifierResult.Metadata.VerifierDestAddress = nil
		}

		resultWithSequence := &msgdiscoverypb.VerifierResultWithSequence{
			VerifierResult: verifierResult,
			Sequence:       report.Sequence,
		}
		records = append(records, resultWithSequence)
	}

	h.m.Metrics().RecordMessageSinceNumberOfRecordsReturned(ctx, len(records))
	h.logger(ctx).Tracef("Returning %d records for GetMessagesSinceRequest", len(records))

	for _, report := range batch.Reports {
		h.logger(ctx).Tracef("Report MessageID: %x, Sequence: %d, Verifications: %d", report.MessageID, report.Sequence, len(report.Verifications))
	}

	return &msgdiscoverypb.GetMessagesSinceResponse{
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
