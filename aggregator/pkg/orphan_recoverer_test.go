package aggregator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestOrphanRecoverer_HealthCheck_NotStarted(t *testing.T) {
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	agg := aggregation_mocks.NewMockAggregationTriggerer(t)
	metrics := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:         true,
			IntervalSeconds: 60,
			MaxAgeHours:     24,
		},
	}

	recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)

	err := recoverer.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestOrphanRecoverer_HealthCheck_ReportsStoppedAfterContextCancellation(t *testing.T) {
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	agg := aggregation_mocks.NewMockAggregationTriggerer(t)
	metrics := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

	orphansChan := make(chan model.OrphanedKey)
	errChan := make(chan error)
	close(orphansChan)
	close(errChan)

	store.EXPECT().OrphanedKeyStats(mock.Anything, mock.Anything).Return(&model.OrphanStats{}, nil).Maybe()
	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything).Return(orphansChan, errChan).Maybe()
	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:         true,
			IntervalSeconds: 1,
			MaxAgeHours:     24,
		},
	}

	recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error)
	go func() {
		done <- recoverer.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, recoverer.Ready())

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recoverer did not stop in time")
	}

	err := recoverer.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped")
}

func TestOrphanRecoverer_RecoversPanicAndKeepsRunning(t *testing.T) {
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	agg := aggregation_mocks.NewMockAggregationTriggerer(t)
	metrics := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

	panicCount := 0
	store.EXPECT().OrphanedKeyStats(mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ time.Time) {
			panicCount++
			if panicCount == 1 {
				panic("simulated panic in OrphanedKeyStats")
			}
		}).Return(&model.OrphanStats{}, nil).Maybe()

	orphansChan := make(chan model.OrphanedKey)
	errChan := make(chan error)
	close(orphansChan)
	close(errChan)
	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything).Return(orphansChan, errChan).Maybe()

	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:         true,
			IntervalSeconds: 1,
			MaxAgeHours:     24,
		},
	}

	recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = recoverer.Start(ctx)
	}()

	// Wait for the first scan (which panics) and the second scan (which succeeds)
	time.Sleep(1500 * time.Millisecond)

	// Service should still be running and healthy after recovering from panic
	require.NoError(t, recoverer.Ready())
	require.GreaterOrEqual(t, panicCount, 1, "panic should have occurred at least once")
}

func TestOrphanRecoverer_UnhealthyAfterConsecutivePanics(t *testing.T) {
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	agg := aggregation_mocks.NewMockAggregationTriggerer(t)
	metrics := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

	panicCount := 0
	store.EXPECT().OrphanedKeyStats(mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ time.Time) {
			panicCount++
			// Panic on all calls
			panic("simulated consecutive panic")
		}).Return(&model.OrphanStats{}, nil).Maybe()

	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:         true,
			IntervalSeconds: 1,
			MaxAgeHours:     24,
		},
	}

	recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = recoverer.Start(ctx)
	}()

	// Wait for at least 3 consecutive panics (interval is 1s, so 3.5s should be enough)
	time.Sleep(3500 * time.Millisecond)

	// Service should report unhealthy after 3 consecutive panics
	err := recoverer.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consecutive panics")
	require.GreaterOrEqual(t, panicCount, 3, "should have panicked at least 3 times")
}
