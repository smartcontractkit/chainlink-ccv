// Package aggregation provides commit report aggregation functionality for the aggregator service.
package aggregation

import (
	"context"
	"sync"
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
	storage                       common.CommitVerificationStore
	sink                          common.Sink
	messageIDChan                 chan aggregationRequest
	quorum                        QuorumValidator
	l                             logger.SugaredLogger
	monitoring                    common.AggregatorMonitoring
	orphanRecoveryMutex           sync.Mutex
	orphanRecoveryTicker          *time.Ticker
	orphanRecoveryIntervalMinutes int
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

func (c *CommitReportAggregator) checkAggregationAndSubmitComplete(ctx context.Context, messageID model.MessageID, committeeID model.CommitteeID) error {
	lggr := c.logger(ctx)
	lggr.Debugw("Starting aggregation check")
	lggr = lggr.With("messageID", messageID, "committee", committeeID)
	lggr.Infof("Checking aggregation for message ID: %s, committee: %s", messageID, committeeID)
	verifications, err := c.storage.ListCommitVerificationByMessageID(ctx, messageID, committeeID)
	if err != nil {
		lggr.Errorw("Failed to list verifications", "error", err)
		return err
	}

	lggr.Debugw("Verifications retrieved", "count", len(verifications))

	aggregatedReport := &model.CommitAggregatedReport{
		MessageID:     messageID,
		CommitteeID:   committeeID,
		Verifications: verifications,
	}

	quorumMet, err := c.quorum.CheckQuorum(ctx, aggregatedReport)
	if err != nil {
		lggr.Errorw("Failed to check quorum", "error", err)
		return err
	}

	if quorumMet {
		if err := c.sink.SubmitReport(ctx, aggregatedReport); err != nil {
			lggr.Errorw("Failed to submit report", "error", err)
			return err
		}
		timeToAggregation := aggregatedReport.CalculateTimeToAggregation(time.Now())
		lggr.Infow("Report submitted successfully", "verifications", len(verifications), "timeToAggregation", timeToAggregation)
		c.metrics(ctx).IncrementCompletedAggregations(ctx)
		c.metrics(ctx).RecordTimeToAggregation(ctx, timeToAggregation.Milliseconds())
	} else {
		lggr.Infow("Quorum not met, not submitting report", "verifications", len(verifications))
	}

	return nil
}

// RecoverOrphans finds verification records that have not been aggregated yet and triggers aggregation for them.
// This is used to recover from scenarios where the service crashed before processing channel-queued aggregation requests.
func (c *CommitReportAggregator) RecoverOrphans(ctx context.Context) {
	// Try to acquire the mutex with a non-blocking call
	if !c.orphanRecoveryMutex.TryLock() {
		c.l.Debug("Orphan recovery already running, skipping")
		return
	}
	defer c.orphanRecoveryMutex.Unlock()

	c.recoverOrphansInternal(ctx)
}

// StartBackground begins processing aggregation requests in the background.
// It also performs orphan recovery on startup and schedules periodic recovery to handle missed aggregations.
func (c *CommitReportAggregator) StartBackground(ctx context.Context) {
	// Perform orphan recovery on startup in background
	go c.RecoverOrphans(ctx)

	// Start scheduled orphan recovery using configured interval
	recoveryInterval := time.Duration(c.orphanRecoveryIntervalMinutes) * time.Minute
	c.orphanRecoveryTicker = time.NewTicker(recoveryInterval)
	go func() {
		defer c.orphanRecoveryTicker.Stop()
		for {
			select {
			case <-c.orphanRecoveryTicker.C:
				go c.RecoverOrphans(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case request := <-c.messageIDChan:
				go func() {
					c.monitoring.Metrics().DecrementPendingAggregationsChannelBuffer(context.Background(), 1)
					ctx := scope.WithMessageID(context.Background(), request.MessageID)
					ctx = scope.WithCommitteeID(ctx, request.CommitteeID)
					err := c.checkAggregationAndSubmitComplete(ctx, request.MessageID, request.CommitteeID)
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

// Stop gracefully shuts down the aggregator, stopping the scheduled orphan recovery.
func (c *CommitReportAggregator) Stop() {
	if c.orphanRecoveryTicker != nil {
		c.orphanRecoveryTicker.Stop()
	}
}

// TriggerOrphanRecovery manually triggers orphan recovery if not already running.
// Returns true if recovery was started, false if already running.
func (c *CommitReportAggregator) TriggerOrphanRecovery(ctx context.Context) bool {
	if c.orphanRecoveryMutex.TryLock() {
		go func() {
			defer c.orphanRecoveryMutex.Unlock()
			c.recoverOrphansInternal(ctx)
		}()
		return true
	}
	return false
}

// recoverOrphansInternal contains the core orphan recovery logic without mutex handling.
func (c *CommitReportAggregator) recoverOrphansInternal(ctx context.Context) {
	lggr := c.logger(ctx)
	lggr.Infow("Starting orphan recovery")

	// Stream orphaned (messageID, committeeID) pairs from verification records
	pairCh, errCh := c.storage.ListOrphanedMessageCommitteePairs(ctx)

	orphanCount := 0
	totalPairs := 0

	for {
		select {
		case pair, ok := <-pairCh:
			if !ok {
				lggr.Infow("Completed orphan recovery", "totalPairs", totalPairs, "orphansFound", orphanCount)
				return
			}

			totalPairs++

			if err := c.CheckAggregation(pair.MessageID, pair.CommitteeID); err != nil {
				lggr.Errorw("Failed to trigger aggregation for orphaned message",
					"messageID", pair.MessageID,
					"committeeID", pair.CommitteeID,
					"error", err)
				continue
			}

			orphanCount++
			lggr.Infow("Triggered recovery aggregation for orphaned message",
				"messageID", pair.MessageID,
				"committeeID", pair.CommitteeID)

		case err, ok := <-errCh:
			if !ok {
				if pairCh == nil {
					lggr.Infow("Completed orphan recovery", "totalPairs", totalPairs, "orphansFound", orphanCount)
					return
				}
				errCh = nil
				continue
			}

			if err != nil {
				lggr.Errorw("Error during orphan recovery", "error", err)
				continue
			}

		case <-ctx.Done():
			lggr.Warnw("Orphan recovery cancelled", "error", ctx.Err(), "processedPairs", totalPairs, "orphansRecovered", orphanCount)
			return
		}
	}
}

// NewCommitReportAggregator creates a new instance of CommitReportAggregator with the provided dependencies.
// It initializes the aggregator with a storage backend for commit verifications, a sink for forwarding
// completed reports, and configuration settings for committee quorum requirements.
//
// Parameters:
//   - storage: Interface for storing and retrieving commit verifications
//   - sink: Interface for submitting aggregated reports
//   - quorum: Interface for validating quorum requirements
//   - logger: Logger instance for structured logging
//   - monitoring: Interface for metrics and monitoring
//   - config: Aggregation configuration containing channel size and recovery interval
//
// Returns:
//   - *CommitReportAggregator: A new aggregator instance ready to process commit reports
//
// The returned aggregator must have StartBackground called to begin processing aggregation requests.
func NewCommitReportAggregator(storage common.CommitVerificationStore, sink common.Sink, quorum QuorumValidator, logger logger.SugaredLogger, monitoring common.AggregatorMonitoring, config *model.AggregationConfig) *CommitReportAggregator {
	return &CommitReportAggregator{
		storage:                       storage,
		sink:                          sink,
		messageIDChan:                 make(chan aggregationRequest, config.MessageChannelSize),
		quorum:                        quorum,
		monitoring:                    monitoring,
		l:                             logger,
		orphanRecoveryIntervalMinutes: config.OrphanRecoveryIntervalMinutes,
		// orphanRecoveryMutex is initialized as unlocked by default
	}
}
