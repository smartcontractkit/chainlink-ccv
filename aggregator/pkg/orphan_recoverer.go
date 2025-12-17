package aggregator

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/handlers"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type OrphanRecoverer struct {
	config     *model.AggregatorConfig
	aggregator handlers.AggregationTriggerer
	storage    common.CommitVerificationStore
	logger     logger.SugaredLogger
	metrics    common.AggregatorMetricLabeler
}

func (o *OrphanRecoverer) Start(ctx context.Context) error {
	orphanRecoveryConfig := o.config.OrphanRecovery

	o.logger.Infow("Starting orphan recovery process",
		"interval", orphanRecoveryConfig.IntervalSeconds)

	for {
		now := time.Now()
		o.logger.Info("Initiating orphan recovery scan")
		err := o.RecoverOrphans(ctx)
		if err != nil {
			o.logger.Errorw("Orphan recovery scan failed", "error", err)
		} else {
			o.logger.Info("Orphan recovery scan completed successfully")
		}
		duration := time.Since(now)
		o.metrics.RecordOrphanRecoveryDuration(ctx, duration)
		o.logger.Infow("Orphan recovery scan finished",
			"duration", duration)
		if duration < time.Duration(orphanRecoveryConfig.IntervalSeconds)*time.Second {
			sleepDuration := time.Duration(orphanRecoveryConfig.IntervalSeconds)*time.Second - duration
			o.logger.Infow("Sleeping until next orphan recovery scan",
				"sleepDuration", sleepDuration)
			select {
			case <-time.After(sleepDuration):
			case <-ctx.Done():
				o.logger.Info("Orphan recovery process stopping due to context cancellation")
				return ctx.Err()
			}
		}
	}
}

// StartCleanup runs the orphan cleanup process in a separate loop.
// This deletes expired orphan records based on MaxAgeHours configuration.
func (o *OrphanRecoverer) StartCleanup(ctx context.Context) error {
	orphanRecoveryConfig := o.config.OrphanRecovery

	o.logger.Infow("Starting orphan cleanup process",
		"interval", orphanRecoveryConfig.CleanupIntervalSeconds,
		"maxAgeHours", orphanRecoveryConfig.MaxAgeHours)

	for {
		now := time.Now()
		o.logger.Info("Initiating orphan cleanup")
		err := o.deleteExpiredOrphans(ctx)
		if err != nil {
			o.logger.Errorw("Orphan cleanup failed", "error", err)
			o.metrics.IncrementOrphanRecoveryErrors(ctx)
		} else {
			o.logger.Info("Orphan cleanup completed successfully")
		}
		duration := time.Since(now)
		o.metrics.RecordOrphanCleanupDuration(ctx, duration)
		o.logger.Infow("Orphan cleanup finished", "duration", duration)

		if duration < time.Duration(orphanRecoveryConfig.CleanupIntervalSeconds)*time.Second {
			sleepDuration := time.Duration(orphanRecoveryConfig.CleanupIntervalSeconds)*time.Second - duration
			o.logger.Infow("Sleeping until next orphan cleanup",
				"sleepDuration", sleepDuration)
			select {
			case <-time.After(sleepDuration):
			case <-ctx.Done():
				o.logger.Info("Orphan cleanup process stopping due to context cancellation")
				return ctx.Err()
			}
		}
	}
}

func (o *OrphanRecoverer) calculateCutoffFromNow() time.Time {
	return time.Now().Add(-time.Duration(o.config.OrphanRecovery.MaxAgeHours) * time.Hour)
}

// RecoverOrphans scans for orphaned verification records and attempts to re-aggregate them.
// This method is designed to be called periodically to recover from cases where verifications
// were submitted but aggregation failed due to transient errors.
func (o *OrphanRecoverer) RecoverOrphans(ctx context.Context) error {
	cutoff := o.calculateCutoffFromNow()

	stats, err := o.storage.OrphanedKeyStats(ctx, cutoff)
	if err != nil {
		o.logger.Errorw("Failed to get orphan stats", "error", err)
		o.metrics.IncrementOrphanRecoveryErrors(ctx)
	} else {
		o.metrics.SetOrphanBacklog(ctx, stats.NonExpiredCount)
		o.metrics.SetOrphanExpiredBacklog(ctx, stats.ExpiredCount)
		o.logger.Infow("Orphan stats",
			"nonExpired", stats.NonExpiredCount,
			"expired", stats.ExpiredCount,
			"total", stats.TotalCount)
	}

	orphansChan, errorChan := o.storage.ListOrphanedKeys(ctx, cutoff)

	var processedCount, errorCount int

	for {
		select {
		case orphanRecord, ok := <-orphansChan:
			if !ok {
				o.logger.Infow("Orphan recovery completed",
					"processed", processedCount,
					"errors", errorCount)
				return nil
			}

			err := o.processOrphanedRecord(orphanRecord)
			if err != nil {
				o.logger.Errorw("Failed to process orphaned record",
					"messageID", fmt.Sprintf("%x", orphanRecord.MessageID),
					"aggregationKey", orphanRecord.AggregationKey,
					"error", err)
				errorCount++
				o.metrics.IncrementOrphanRecoveryErrors(ctx)
			} else {
				o.logger.Debugw("Successfully processed orphaned record",
					"messageID", fmt.Sprintf("%x", orphanRecord.MessageID),
					"aggregationKey", orphanRecord.AggregationKey)
				processedCount++
			}

		case err, ok := <-errorChan:
			if !ok {
				o.logger.Infow("Orphan recovery completed",
					"processed", processedCount,
					"errors", errorCount)
				return nil
			}

			if err != nil {
				o.logger.Errorw("Error during orphan scanning", "error", err)
				o.metrics.IncrementOrphanRecoveryErrors(ctx)
				return fmt.Errorf("orphan recovery failed: %w", err)
			}

		case <-ctx.Done():
			o.logger.Warn("Orphan recovery cancelled by context")
			return ctx.Err()
		}
	}
}

func (o *OrphanRecoverer) deleteExpiredOrphans(ctx context.Context) error {
	cutoff := o.calculateCutoffFromNow()

	totalDeleted := 0
	for {
		batchDeleted, err := o.deleteExpiredOrphansBatch(ctx, cutoff)
		if err != nil {
			return err
		}

		totalDeleted += batchDeleted
		if batchDeleted == 0 {
			break
		}

		o.logger.Debugw("Deleted batch of expired orphans", "batchSize", batchDeleted)
	}

	o.logger.Infow("Expired orphan deletion completed", "deleted", totalDeleted)
	o.metrics.IncrementOrphanRecordsExpired(ctx, totalDeleted)
	return nil
}

func (o *OrphanRecoverer) deleteExpiredOrphansBatch(ctx context.Context, cutoff time.Time) (int, error) {
	deletedChan, errChan := o.storage.DeleteExpiredOrphans(ctx, cutoff, o.config.OrphanRecovery.DeleteBatchSize)

	batchCount := 0
	for {
		select {
		case deleted, ok := <-deletedChan:
			if !ok {
				return batchCount, nil
			}
			batchCount++
			o.logger.Debugw("Deleted expired orphan record",
				"messageID", fmt.Sprintf("%x", deleted.MessageID),
				"aggregationKey", deleted.AggregationKey,
				"signerAddress", deleted.SignerAddress)

		case err, ok := <-errChan:
			if !ok {
				return batchCount, nil
			}
			if err != nil {
				return batchCount, fmt.Errorf("error deleting expired orphans: %w", err)
			}

		case <-ctx.Done():
			return batchCount, ctx.Err()
		}
	}
}

// processOrphanedRecord attempts to re-aggregate an orphaned verification record.
func (o *OrphanRecoverer) processOrphanedRecord(record model.OrphanedKey) error {
	err := o.aggregator.CheckAggregation(record.MessageID, record.AggregationKey)
	if err != nil {
		return fmt.Errorf("failed to trigger aggregation check: %w", err)
	}

	o.logger.Debugw("Successfully triggered re-aggregation check",
		"messageID", fmt.Sprintf("%x", record.MessageID),
		"aggregationKey", record.AggregationKey)

	return nil
}

func NewOrphanRecoverer(store common.CommitVerificationStore, aggregator handlers.AggregationTriggerer, config *model.AggregatorConfig, l logger.SugaredLogger, metrics common.AggregatorMetricLabeler) *OrphanRecoverer {
	return &OrphanRecoverer{
		config:     config,
		aggregator: aggregator,
		storage:    store,
		logger:     l.With("component", "OrphanRecoverer"),
		metrics:    metrics,
	}
}
