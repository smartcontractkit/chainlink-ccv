package aggregation

import (
	"context"
	"time"

	"github.com/sourcegraph/conc/pool"

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
	storage               common.CommitVerificationStore
	aggregatedStore       common.CommitVerificationAggregatedStore
	sink                  common.Sink
	aggregationKeyChan    chan aggregationRequest
	backgroundWorkerCount int
	quorum                QuorumValidator
	l                     logger.SugaredLogger
	monitoring            common.AggregatorMonitoring
	done                  chan struct{}
}

type aggregationRequest struct {
	// CommitteeID is the ID of the committee for the aggregation request.
	CommitteeID    model.CommitteeID
	AggregationKey model.AggregationKey
	MessageID      model.MessageID
}

func (c *CommitReportAggregator) HealthCheck(ctx context.Context) *common.ComponentHealth {
	result := &common.ComponentHealth{
		Name:      "aggregation_service",
		Timestamp: time.Now(),
	}

	select {
	case <-c.done:
		result.Status = common.HealthStatusUnhealthy
		result.Message = "aggregation worker stopped"
		return result
	default:
	}

	pending := len(c.aggregationKeyChan)
	capacity := cap(c.aggregationKeyChan)

	if pending >= capacity {
		result.Status = common.HealthStatusDegraded
		result.Message = "aggregation queue full"
		return result
	}

	if float64(pending)/float64(capacity) > 0.8 {
		result.Status = common.HealthStatusDegraded
		result.Message = "aggregation queue high"
		return result
	}

	result.Status = common.HealthStatusHealthy
	result.Message = "aggregation queue healthy"
	return result
}

// CheckAggregation enqueues a new aggregation request for the specified message ID.
func (c *CommitReportAggregator) CheckAggregation(messageID model.MessageID, aggregationKey model.AggregationKey, committeeID model.CommitteeID) error {
	request := aggregationRequest{
		MessageID:      messageID,
		CommitteeID:    committeeID,
		AggregationKey: aggregationKey,
	}
	select {
	case c.aggregationKeyChan <- request:
		c.monitoring.Metrics().IncrementPendingAggregationsChannelBuffer(context.Background(), 1)
	default:
		return common.ErrAggregationChannelFull
	}
	return nil
}

func (c *CommitReportAggregator) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, c.l)
}

func (c *CommitReportAggregator) metrics(ctx context.Context) common.AggregatorMetricLabeler {
	return scope.AugmentMetrics(ctx, c.monitoring.Metrics())
}

func deduplicateVerificationsByParticipant(verifications []*model.CommitVerificationRecord) []*model.CommitVerificationRecord {
	if len(verifications) <= 1 {
		return verifications
	}

	// Map from participant address (hex string) to the verification record
	participantMap := make(map[string]*model.CommitVerificationRecord)

	for _, verification := range verifications {
		if verification.IdentifierSigner == nil || len(verification.IdentifierSigner.ParticipantID) == 0 {
			continue
		}

		participantID := verification.IdentifierSigner.ParticipantID
		existing, exists := participantMap[participantID]

		if !exists || verification.GetTimestamp().After(existing.GetTimestamp()) {
			participantMap[participantID] = verification
		}
	}

	result := make([]*model.CommitVerificationRecord, 0, len(participantMap))
	for _, verification := range participantMap {
		result = append(result, verification)
	}

	return result
}

// shouldSkipAggregationDueToExistingQuorum checks if we should skip creating a new aggregation
// because an existing aggregated report already meets quorum requirements.
// Returns true if aggregation should be skipped, false otherwise.
func (c *CommitReportAggregator) shouldSkipAggregationDueToExistingQuorum(ctx context.Context, messageID model.MessageID, committeeID model.CommitteeID) (bool, error) {
	lggr := c.logger(ctx)

	// Check if aggregated store is available
	if c.aggregatedStore == nil {
		lggr.Warnw("No aggregated store available, cannot check existing aggregations")
		return false, nil
	}

	// Try to get existing aggregated report
	existingReport, err := c.aggregatedStore.GetCCVData(ctx, messageID, committeeID)
	if err != nil {
		lggr.Warnw("Failed to check for existing aggregated report", "error", err)
		return false, nil // On error, proceed with aggregation
	}

	// If no existing report, don't skip
	if existingReport == nil {
		lggr.Debugw("No existing aggregated report found, proceeding with aggregation")
		return false, nil
	}

	// Check if the existing report still meets quorum
	quorumMet, err := c.quorum.CheckQuorum(ctx, existingReport)
	if err != nil {
		lggr.Warnw("Failed to check quorum for existing report", "error", err)
		return false, nil // On error, proceed with aggregation
	}

	if quorumMet {
		lggr.Infow("Skipping aggregation: existing report already meets quorum",
			"existingReportTimestamp", existingReport.GetMostRecentVerificationTimestamp(),
			"verificationCount", len(existingReport.Verifications))
		return true, nil
	}

	lggr.Infow("Existing report no longer meets quorum, proceeding with new aggregation",
		"existingReportTimestamp", existingReport.GetMostRecentVerificationTimestamp(),
		"verificationCount", len(existingReport.Verifications))
	return false, nil
}

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, request aggregationRequest) (*model.CommitAggregatedReport, error) {
	lggr := c.logger(ctx)
	lggr.Infof("Checking aggregation for message", request.MessageID, request.CommitteeID, request.AggregationKey)

	shouldSkip, err := c.shouldSkipAggregationDueToExistingQuorum(ctx, request.MessageID, request.CommitteeID)
	if err != nil {
		lggr.Errorw("Error checking existing quorum", "error", err)
	} else if shouldSkip {
		lggr.Infow("Skipping aggregation due to existing quorum")
		return nil, nil
	}

	verifications, err := c.storage.ListCommitVerificationByAggregationKey(ctx, request.MessageID, request.AggregationKey, request.CommitteeID)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
		return nil, err
	}

	lggr.Debugw("Verifications retrieved", "count", len(verifications))

	dedupedVerifications := deduplicateVerificationsByParticipant(verifications)
	if len(dedupedVerifications) < len(verifications) {
		lggr.Infow("Deduplicated verifications", "original", len(verifications), "deduplicated", len(dedupedVerifications))
	}

	winningReceiptBlobs, err := selectWinningReceiptBlobSet(dedupedVerifications)
	if err != nil {
		lggr.Errorw("Failed to select winning receipt blob set", "error", err)
		return nil, err
	}

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:           request.MessageID,
		CommitteeID:         request.CommitteeID,
		Verifications:       dedupedVerifications,
		WinningReceiptBlobs: winningReceiptBlobs,
	}

	mostRecentTimestamp := aggregatedReport.GetMostRecentVerificationTimestamp()

	lggr.Debugw("Aggregated report created", "timestamp", mostRecentTimestamp, "verificationCount", len(dedupedVerifications))

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
		c.metrics(ctx).RecordTimeToAggregation(ctx, timeToAggregation)
	} else {
		lggr.Infow("Quorum not met, not submitting report", "verifications", len(verifications))
	}

	return nil, nil
}

// StartBackground begins processing aggregation requests in the background.
func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	c.done = make(chan struct{})
	p := pool.New().WithMaxGoroutines(c.backgroundWorkerCount).WithContext(ctx)
	go func() {
		for {
			select {
			case request := <-c.aggregationKeyChan:
				p.Go(func(poolCtx context.Context) error {
					c.monitoring.Metrics().DecrementPendingAggregationsChannelBuffer(poolCtx, 1)
					poolCtx = scope.WithCommitteeID(poolCtx, request.CommitteeID)
					poolCtx = scope.WithAggregationKey(poolCtx, request.AggregationKey)
					poolCtx = scope.WithMessageID(poolCtx, request.MessageID)
					_, err := c.checkAggregationAndSubmitComplete(poolCtx, request)
					return err
				})
			case <-ctx.Done():
				close(c.done)
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
//   - aggregatedStore: Interface for querying existing aggregated reports (can be nil to disable the feature)
//   - sink: Interface for submitting aggregated reports
//   - config: Configuration containing committee and quorum settings
//
// Returns:
//   - *CommitReportAggregator: A new aggregator instance ready to process commit reports
//
// The returned aggregator must have StartBackground called to begin processing aggregation requests.
func NewCommitReportAggregator(storage common.CommitVerificationStore, aggregatedStore common.CommitVerificationAggregatedStore, sink common.Sink, quorum QuorumValidator, config *model.AggregatorConfig, logger logger.SugaredLogger, monitoring common.AggregatorMonitoring) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:               storage,
		aggregatedStore:       aggregatedStore,
		sink:                  sink,
		aggregationKeyChan:    make(chan aggregationRequest, config.Aggregation.ChannelBufferSize),
		backgroundWorkerCount: config.Aggregation.BackgroundWorkerCount,
		quorum:                quorum,
		monitoring:            monitoring,
		l:                     logger,
	}
}
