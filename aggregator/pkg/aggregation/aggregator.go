package aggregation

import (
	"context"
	"math"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type QuorumValidator interface {
	// CheckQuorum checks if the aggregated report meets the quorum requirements.
	CheckQuorum(ctx context.Context, report *model.CommitAggregatedReport) (bool, error)
}

// CommitReportAggregator is responsible for aggregating commit reports from multiple verifiers.
// It manages the verification and storage of commit reports through a configurable storage backend,
// processes aggregation requests via a message channel, and forwards verified reports to a sink.
type CommitReportAggregator struct {
	storage       common.CommitVerificationStore
	sink          common.Sink
	messageIDChan chan aggregationRequest
	quorum        QuorumValidator
	l             logger.SugaredLogger
	monitoring    common.AggregatorMonitoring
}

type aggregationRequest struct {
	// CommitteeID is the ID of the committee for the aggregation request.
	CommitteeID model.CommitteeID
	MessageID   model.MessageID
}

// CheckAggregation enqueues a new aggregation request for the specified message ID.
func (c *CommitReportAggregator) CheckAggregation(messageID model.MessageID, committeeID model.CommitteeID) error {
	go func() {
		c.monitoring.Metrics().IncrementPendingAggregationsChannelBuffer(context.Background(), 1)
		c.messageIDChan <- aggregationRequest{
			MessageID:   messageID,
			CommitteeID: committeeID,
		}
	}()
	return nil
}

func (c *CommitReportAggregator) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, c.l)
}

func (c *CommitReportAggregator) metrics(ctx context.Context) common.AggregatorMetricLabeler {
	return scope.AugmentMetrics(ctx, c.monitoring.Metrics())
}

func normalizeTimestampToSeconds(timestamp int64) int64 {
	if timestamp <= 0 {
		return timestamp
	}
	digits := int(math.Log10(float64(timestamp))) + 1
	if digits > 10 {
		divisor := int64(math.Pow10(digits - 10))
		return timestamp / divisor
	}
	return timestamp
}

func deduplicateVerificationsByParticipant(verifications []*model.CommitVerificationRecord) []*model.CommitVerificationRecord {
	if len(verifications) <= 1 {
		return verifications
	}

	// Map from participant address (hex string) to the verification record
	participantMap := make(map[string]*model.CommitVerificationRecord)

	for _, verification := range verifications {
		if verification.IdentifierSigner == nil || len(verification.IdentifierSigner.Address) == 0 {
			continue
		}

		addressKey := string(verification.IdentifierSigner.Address)
		existing, exists := participantMap[addressKey]

		if !exists || verification.GetTimestamp() > existing.GetTimestamp() {
			participantMap[addressKey] = verification
		}
	}

	result := make([]*model.CommitVerificationRecord, 0, len(participantMap))
	for _, verification := range participantMap {
		result = append(result, verification)
	}

	return result
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, messageID model.MessageID, committeeID model.CommitteeID) (*model.CommitAggregatedReport, error) {
	lggr := c.logger(ctx)
	lggr.Debugw("Starting aggregation check")
	lggr = lggr.With("messageID", messageID, "committee", committeeID)
	lggr.Infof("Checking aggregation for message ID: %x, committee: %s", messageID, committeeID)
	verifications, err := c.storage.ListCommitVerificationByMessageID(ctx, messageID, committeeID)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
		return nil, err
	}

	lggr.Debugw("Verifications retrieved", "count", len(verifications))

	dedupedVerifications := deduplicateVerificationsByParticipant(verifications)
	if len(dedupedVerifications) < len(verifications) {
		lggr.Infow("Deduplicated verifications", "original", len(verifications), "deduplicated", len(dedupedVerifications))
	}

	var mostRecentTimestamp int64
	for _, verification := range dedupedVerifications {
		verificationTimestamp := normalizeTimestampToSeconds(verification.GetTimestamp())
		if verificationTimestamp > mostRecentTimestamp {
			mostRecentTimestamp = verificationTimestamp
		}
	}

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		CommitteeID:   committeeID,
		Verifications: dedupedVerifications,
		Timestamp:     mostRecentTimestamp,
	}

	quorumMet, err := c.quorum.CheckQuorum(ctx, aggregatedReport)
	if err != nil {
		lggr.Errorw("Failed to check quorum", "error", err)
		return nil, err
	}

	if quorumMet {
		if err := c.sink.SubmitReport(ctx, aggregatedReport); err != nil {
			lggr.Errorw("Failed to submit report", "error", err)
			return nil, err
		}
		timeToAggregation := aggregatedReport.CalculateTimeToAggregation(time.Now())
		lggr.Infow("Report submitted successfully", "verifications", len(verifications), "timeToAggregation", timeToAggregation)
		c.metrics(ctx).IncrementCompletedAggregations(ctx)
		c.metrics(ctx).RecordTimeToAggregation(ctx, timeToAggregation.Milliseconds())
	} else {
		lggr.Infow("Quorum not met, not submitting report", "verifications", len(verifications))
	}

	return nil, nil
}

// StartBackground begins processing aggregation requests in the background.
func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	go func() {
		for {
			select {
			case request := <-c.messageIDChan:
				go func() {
					c.monitoring.Metrics().DecrementPendingAggregationsChannelBuffer(context.Background(), 1)
					ctx := scope.WithMessageID(context.Background(), request.MessageID)
					ctx = scope.WithCommitteeID(ctx, request.CommitteeID)
					_, err := c.checkAggregationAndSubmitComplete(ctx, request.MessageID, request.CommitteeID)
					if err != nil {
						c.logger(ctx).Errorw("Failed to process aggregation request", "error", err)
					}
				}()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// NewCommitReportAggregator creates a new instance of CommitReportAggregator with the provided dependencies.
// It initializes the aggregator with a storage backend for commit verifications, a sink for forwarding
// completed reports, and configuration settings for committee quorum requirements.
//
// Parameters:
//   - storage: Interface for storing and retrieving commit verifications
//   - sink: Interface for submitting aggregated reports
//   - config: Configuration containing committee and quorum settings
//
// Returns:
//   - *CommitReportAggregator: A new aggregator instance ready to process commit reports
//
// The returned aggregator must have StartBackground called to begin processing aggregation requests.
func NewCommitReportAggregator(storage common.CommitVerificationStore, sink common.Sink, quorum QuorumValidator, logger logger.SugaredLogger, monitoring common.AggregatorMonitoring) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:       storage,
		sink:          sink,
		messageIDChan: make(chan aggregationRequest, 1000),
		quorum:        quorum,
		monitoring:    monitoring,
		l:             logger,
	}
}
