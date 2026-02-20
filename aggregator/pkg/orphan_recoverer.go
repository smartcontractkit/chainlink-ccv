package aggregator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/handlers"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.HealthReporter = (*OrphanRecoverer)(nil)

type OrphanRecoverer struct {
	config        *model.AggregatorConfig
	aggregator    handlers.AggregationTriggerer
	storage       common.CommitVerificationStore
	logger        logger.SugaredLogger
	metricLabeler common.AggregatorMetricLabeler

	mu                sync.RWMutex
	done              chan struct{}
	lastError         error
	consecutiveErrors uint
}

func (o *OrphanRecoverer) metrics(ctx context.Context) common.AggregatorMetricLabeler {
	metrics := scope.AugmentMetrics(ctx, o.metricLabeler)
	metrics = metrics.With("component", "orphan_recoverer")
	return metrics
}

func (o *OrphanRecoverer) Start(ctx context.Context) error {
	o.mu.Lock()
	o.done = make(chan struct{})
	o.mu.Unlock()

	defer func() {
		close(o.done)
	}()

	orphanRecoveryConfig := o.config.OrphanRecovery

	o.logger.Infow("Starting orphan recovery process",
		"interval", orphanRecoveryConfig.Interval)

	for {
		now := time.Now()
		o.logger.Info("Initiating orphan recovery scan")

		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					o.logger.Errorw("Panic during orphan recovery scan", "panic", r)
					o.metrics(ctx).IncrementPanics(ctx)
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			return o.RecoverOrphans(ctx)
		}()

		o.mu.Lock()
		o.lastError = err
		if err != nil {
			o.consecutiveErrors++
		} else {
			o.consecutiveErrors = 0
		}
		o.mu.Unlock()

		duration := time.Since(now)
		o.metrics(ctx).RecordOrphanRecoveryDuration(ctx, duration)
		o.logger.Infow("Orphan recovery scan finished",
			"duration", duration)
		if duration < orphanRecoveryConfig.Interval {
			sleepDuration := orphanRecoveryConfig.Interval - duration
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

func (o *OrphanRecoverer) calculateCutoffFromNow() time.Time {
	return time.Now().Add(-o.config.OrphanRecovery.MaxAge)
}

// RecoverOrphans scans for orphaned verification records and attempts to re-aggregate them.
// This method is designed to be called periodically to recover from cases where verifications
// were submitted but aggregation failed due to transient errors.
func (o *OrphanRecoverer) RecoverOrphans(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, o.config.OrphanRecovery.ScanTimeout)
	defer cancel()

	cutoff := o.calculateCutoffFromNow()

	stats, err := o.storage.OrphanedKeyStats(ctx, cutoff)
	if err != nil {
		o.logger.Errorw("Failed to get orphan stats", "error", err)
		o.metrics(ctx).IncrementOrphanRecoveryErrors(ctx)
	} else {
		o.metrics(ctx).SetOrphanBacklog(ctx, stats.NonExpiredCount)
		o.metrics(ctx).SetOrphanExpiredBacklog(ctx, stats.ExpiredCount)
		o.logger.Infow("Orphan stats",
			"nonExpired", stats.NonExpiredCount,
			"expired", stats.ExpiredCount,
			"total", stats.TotalCount)
	}

	orphansChan, errorChan := o.storage.ListOrphanedKeys(ctx, cutoff, o.config.OrphanRecovery.PageSize)

	maxOrphans := o.config.OrphanRecovery.MaxOrphansPerScan
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

			err := o.processOrphanedRecord(ctx, orphanRecord)
			if err != nil {
				o.logger.Errorw("Failed to process orphaned record",
					"messageID", fmt.Sprintf("%x", orphanRecord.MessageID),
					"aggregationKey", orphanRecord.AggregationKey,
					"error", err)
				errorCount++
				o.metrics(ctx).IncrementOrphanRecoveryErrors(ctx)
			} else {
				o.logger.Debugw("Successfully processed orphaned record",
					"messageID", fmt.Sprintf("%x", orphanRecord.MessageID),
					"aggregationKey", orphanRecord.AggregationKey)
				processedCount++
			}

			if processedCount >= maxOrphans {
				o.logger.Error("Reached max orphans per scan",
					"limit", maxOrphans,
					"processed", processedCount)
				return nil
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
				o.metrics(ctx).IncrementOrphanRecoveryErrors(ctx)
				return fmt.Errorf("orphan recovery failed: %w", err)
			}

		case <-ctx.Done():
			o.logger.Warn("Orphan recovery cancelled by context")
			return ctx.Err()
		}
	}
}

// processOrphanedRecord attempts to re-aggregate an orphaned verification record.
func (o *OrphanRecoverer) processOrphanedRecord(ctx context.Context, record model.OrphanedKey) error {
	err := o.aggregator.CheckAggregation(ctx, record.MessageID, record.AggregationKey, model.OrphanRecoveryChannelKey, o.config.OrphanRecovery.CheckAggregationTimeout)
	if err != nil {
		return fmt.Errorf("failed to trigger aggregation check: %w", err)
	}

	o.logger.Debugw("Successfully triggered re-aggregation check",
		"messageID", fmt.Sprintf("%x", record.MessageID),
		"aggregationKey", record.AggregationKey)

	return nil
}

func (o *OrphanRecoverer) Ready() error {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.done == nil {
		return fmt.Errorf("orphan recoverer not started")
	}

	select {
	case <-o.done:
		return fmt.Errorf("orphan recoverer stopped")
	default:
	}

	if o.config.OrphanRecovery.MaxConsecutiveErrors != 0 {
		if o.consecutiveErrors >= o.config.OrphanRecovery.MaxConsecutiveErrors {
			return fmt.Errorf("orphan recovery failed %d times in a row. Last error: %w", o.consecutiveErrors, o.lastError)
		}
	}
	return nil
}

func (o *OrphanRecoverer) HealthReport() map[string]error {
	return map[string]error{o.Name(): o.Ready()}
}

func (o *OrphanRecoverer) Name() string {
	return "orphan_recoverer"
}

func NewOrphanRecoverer(store common.CommitVerificationStore, aggregator handlers.AggregationTriggerer, config *model.AggregatorConfig, l logger.SugaredLogger, metrics common.AggregatorMetricLabeler) *OrphanRecoverer {
	return &OrphanRecoverer{
		config:        config,
		aggregator:    aggregator,
		storage:       store,
		logger:        l.With("component", "OrphanRecoverer"),
		metricLabeler: metrics,
	}
}
