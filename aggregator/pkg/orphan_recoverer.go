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
}

func (o *OrphanRecoverer) Start(ctx context.Context) error {
	orphanRecoveryConfig := o.config.OrphanRecovery

	if !orphanRecoveryConfig.Enabled {
		o.logger.Info("Orphan recovery is disabled in configuration")
		return nil
	}

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

// RecoverOrphans scans for orphaned verification records and attempts to re-aggregate them.
// This method is designed to be called periodically to recover from cases where verifications
// were submitted but aggregation failed due to transient errors.
func (o *OrphanRecoverer) RecoverOrphans(ctx context.Context) error {
	for committeeID := range o.config.Committees {
		// Get channels for orphaned message/committee pairs
		orphansChan, errorChan := o.storage.ListOrphanedMessageIDs(ctx, committeeID)

		var processedCount, errorCount int

		for {
			select {
			case messageID, ok := <-orphansChan:
				if !ok {
					// Channel closed, we're done
					o.logger.Infow("Orphan recovery completed",
						"processed", processedCount,
						"errors", errorCount)
					return nil
				}

				// Process this orphaned record
				err := o.processOrphanedRecord(messageID, committeeID)
				if err != nil {
					o.logger.Errorw("Failed to process orphaned record",
						"messageID", fmt.Sprintf("%x", messageID),
						"committeeID", committeeID,
						"error", err)
					errorCount++
				} else {
					o.logger.Debugw("Successfully processed orphaned record",
						"messageID", fmt.Sprintf("%x", messageID),
						"committeeID", committeeID)
					processedCount++
				}

			case err, ok := <-errorChan:
				if !ok {
					// Error channel closed
					o.logger.Infow("Orphan recovery completed",
						"processed", processedCount,
						"errors", errorCount)
					return nil
				}

				if err != nil {
					o.logger.Errorw("Error during orphan scanning", "error", err)
					return fmt.Errorf("orphan recovery failed: %w", err)
				}

			case <-ctx.Done():
				o.logger.Warn("Orphan recovery cancelled by context")
				return ctx.Err()
			}
		}
	}
	return nil
}

// processOrphanedRecord attempts to re-aggregate an orphaned verification record.
func (o *OrphanRecoverer) processOrphanedRecord(messageID model.MessageID, committeeID string) error { // Trigger aggregation check - this will evaluate if we have enough verifications for quorum
	err := o.aggregator.CheckAggregation(messageID, committeeID)
	if err != nil {
		return fmt.Errorf("failed to trigger aggregation check: %w", err)
	}

	o.logger.Debugw("Successfully triggered re-aggregation check",
		"messageID", fmt.Sprintf("%x", messageID),
		"committeeID", committeeID)

	return nil
}

func NewOrphanRecoverer(store common.CommitVerificationStore, aggregator handlers.AggregationTriggerer, config *model.AggregatorConfig, l logger.SugaredLogger) *OrphanRecoverer {
	return &OrphanRecoverer{
		config:     config,
		aggregator: aggregator,
		storage:    store,
		logger:     l.With("component", "OrphanRecoverer"),
	}
}
