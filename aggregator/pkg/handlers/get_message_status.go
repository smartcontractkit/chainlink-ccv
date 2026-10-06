package handlers

import (
	"bytes"
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

// MessageStatusReader reads the data that the message status API needs.
type MessageStatusReader interface {
	// ListCommitVerificationByMessageID returns the latest record per signer, grouped by aggregation key.
	ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID) (map[model.AggregationKey][]*model.CommitVerificationRecord, error)
	// GetBatchAggregatedReportByMessageIDs returns the latest aggregated report per message ID.
	GetBatchAggregatedReportByMessageIDs(ctx context.Context, messageIDs []model.MessageID) (map[string]*model.CommitAggregatedReport, error)
}

// GetMessageStatusHandler returns the quorum progress for one message ID.
type GetMessageStatusHandler struct {
	storage   MessageStatusReader
	committee *model.Committee
	l         logger.SugaredLogger
}

func (h *GetMessageStatusHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle returns the number of committee verifications, the threshold and the aggregated flag.
func (h *GetMessageStatusHandler) Handle(ctx context.Context, req *committeepb.GetMessageStatusRequest) (*committeepb.GetMessageStatusResponse, error) {
	messageID := req.GetMessageId()
	if len(messageID) != protocol.MessageIDSize {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "message_id must be exactly %d bytes, got %d", protocol.MessageIDSize, len(messageID))
	}
	ctx = scope.WithMessageID(ctx, messageID)
	reqLogger := h.logger(ctx)

	recordsByKey, err := h.storage.ListCommitVerificationByMessageID(ctx, messageID)
	if errors.Is(err, common.ErrTooManyRecords) {
		reqLogger.Warnw("Too many verification records for message", "error", err)
		return nil, grpcstatus.Error(codes.FailedPrecondition, "message has too many verification records")
	}
	if err != nil {
		reqLogger.Errorw("Failed to list verification records", "error", err)
		return nil, grpcstatus.Error(codes.Internal, "failed to retrieve message status")
	}
	if len(recordsByKey) == 0 {
		return nil, grpcstatus.Error(codes.NotFound, "message not found")
	}

	reports, err := h.storage.GetBatchAggregatedReportByMessageIDs(ctx, []model.MessageID{messageID})
	if err != nil {
		reqLogger.Errorw("Failed to retrieve aggregated report", "error", err)
		return nil, grpcstatus.Error(codes.Internal, "failed to retrieve message status")
	}
	report, aggregated := reports[protocol.ByteSlice(messageID).String()]

	countsByKey := make(map[model.AggregationKey]int, len(recordsByKey))
	quorumByKey := make(map[model.AggregationKey]*model.QuorumConfig, len(recordsByKey))
	for key, records := range recordsByKey {
		quorumConfig, ok := h.committee.GetQuorumConfig(records[0].GetSourceChainSelector())
		if !ok {
			continue
		}
		quorumByKey[key] = quorumConfig
		countsByKey[key] = countCommitteeSigners(records, quorumConfig)
	}

	selectedKey, ok := selectAggregationKey(report, aggregated, countsByKey, quorumByKey)
	if !ok {
		reqLogger.Warnw("Quorum config not found for message")
		return nil, grpcstatus.Error(codes.NotFound, "message not found")
	}
	if len(recordsByKey) > 1 {
		h.logMultipleKeys(reqLogger, countsByKey, quorumByKey)
	}

	firstAt, latestAt := committeeVerificationTimes(recordsByKey[selectedKey], quorumByKey[selectedKey])
	resp := &committeepb.GetMessageStatusResponse{
		MessageId:            messageID,
		VerificationCount:    uint32(countsByKey[selectedKey]), //nolint:gosec // count is bounded by the storage row limit
		Threshold:            uint32(quorumByKey[selectedKey].Threshold),
		FirstVerificationAt:  firstAt,
		LatestVerificationAt: latestAt,
	}
	// Aggregated is true when the result API can return the report. Message-discovery reports only need to exist.
	if aggregated && h.isReportServable(report) {
		resp.Aggregated = true
		resp.AggregatedAt = report.WrittenAt.UnixMilli()
	}
	return resp, nil
}

// isReportServable applies the message discovery API checks.
func (h *GetMessageStatusHandler) isReportServable(report *model.CommitAggregatedReport) bool {
	_, err := model.MapAggregatedReportToVerifierResultProto(report, h.committee)
	if err != nil {
		return false
	}

	if bytes.Equal(report.GetVersion(), protocol.MessageDiscoveryVersion) {
		return true
	}

	quorumConfig, ok := h.committee.GetQuorumConfig(report.GetSourceChainSelector())
	if !ok || !model.IsSourceVerifierInCCVAddresses(quorumConfig.GetSourceVerifierAddress(), report.GetMessageCCVAddresses()) {
		return false
	}

	return true
}

// selectAggregationKey uses the key of the report when one exists, else the key with the most committee signers.
func selectAggregationKey(report *model.CommitAggregatedReport, aggregated bool, countsByKey map[model.AggregationKey]int, quorumByKey map[model.AggregationKey]*model.QuorumConfig) (model.AggregationKey, bool) {
	if aggregated {
		if _, ok := quorumByKey[report.AggregationKey]; ok {
			return report.AggregationKey, true
		}
	}
	var selected model.AggregationKey
	found := false
	for key, count := range countsByKey {
		// Compare keys on equal counts so that the result does not depend on the map order.
		if !found || count > countsByKey[selected] || (count == countsByKey[selected] && key < selected) {
			selected, found = key, true
		}
	}
	return selected, found
}

func (h *GetMessageStatusHandler) logMultipleKeys(reqLogger logger.SugaredLogger, countsByKey map[model.AggregationKey]int, quorumByKey map[model.AggregationKey]*model.QuorumConfig) {
	keysWithQuorum := 0
	for key, count := range countsByKey {
		if count >= int(quorumByKey[key].Threshold) {
			keysWithQuorum++
		}
	}
	if keysWithQuorum > 1 {
		reqLogger.Errorw("Quorum reached on more than one aggregation key", "verificationsByAggregationKey", countsByKey)
		return
	}
	reqLogger.Warnw("Verifications found on more than one aggregation key", "verificationsByAggregationKey", countsByKey)
}

func countCommitteeSigners(records []*model.CommitVerificationRecord, quorumConfig *model.QuorumConfig) int {
	signers := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.SignerIdentifier == nil || !quorumConfig.IsSigner(record.SignerIdentifier.Identifier) {
			continue
		}
		signers[record.SignerIdentifier.Identifier.String()] = struct{}{}
	}
	return len(signers)
}

// committeeVerificationTimes returns the first and latest receive times, in Unix milliseconds, of the counted records.
func committeeVerificationTimes(records []*model.CommitVerificationRecord, quorumConfig *model.QuorumConfig) (first, latest int64) {
	for _, record := range records {
		if record.SignerIdentifier == nil || !quorumConfig.IsSigner(record.SignerIdentifier.Identifier) {
			continue
		}
		at := record.GetTimestamp().UnixMilli()
		if first == 0 || at < first {
			first = at
		}
		if at > latest {
			latest = at
		}
	}
	return first, latest
}

// NewGetMessageStatusHandler creates a new GetMessageStatusHandler.
func NewGetMessageStatusHandler(storage MessageStatusReader, committee *model.Committee, l logger.SugaredLogger) *GetMessageStatusHandler {
	return &GetMessageStatusHandler{
		storage:   storage,
		committee: committee,
		l:         l,
	}
}
