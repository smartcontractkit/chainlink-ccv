package aggregator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/handlers"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.HealthReporter = (*OrphanRecoverer)(nil)

const maxConsecutivePanics = 3

type OrphanRecoverer struct {
	config     *model.AggregatorConfig
	aggregator handlers.AggregationTriggerer
	storage    common.CommitVerificationStore
	logger     logger.SugaredLogger
	metrics    common.AggregatorMetricLabeler

	mu                sync.RWMutex
	done              chan struct{}
	lastError         error
	consecutivePanics int
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
		"interval", orphanRecoveryConfig.IntervalSeconds)

	for {
		now := time.Now()
		o.logger.Info("Initiating orphan recovery scan")

		var didPanic bool
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					o.logger.Errorw("Panic during orphan recovery scan", "panic", r)
					didPanic = true
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			return o.RecoverOrphans(ctx)
		}()

		o.mu.Lock()
		o.lastError = err
		if didPanic {
			o.consecutivePanics++
			if o.consecutivePanics >= maxConsecutivePanics {
				o.logger.Errorw("Orphan recoverer unhealthy: too many consecutive panics",
					"consecutivePanics", o.consecutivePanics)
			}
		} else {
			o.consecutivePanics = 0
		}
		o.mu.Unlock()

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

	if o.consecutivePanics >= maxConsecutivePanics {
		return fmt.Errorf("orphan recoverer unhealthy: %d consecutive panics", o.consecutivePanics)
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
		config:     config,
		aggregator: aggregator,
		storage:    store,
		logger:     l.With("component", "OrphanRecoverer"),
		metrics:    metrics,
	}
}
