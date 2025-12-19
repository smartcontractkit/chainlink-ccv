package aggregator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestOrphanRecoverer_HealthCheck_NotStarted(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	metrics := mocks.NewMockAggregatorMetricLabeler(t)

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
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	metrics := mocks.NewMockAggregatorMetricLabeler(t)

	orphansChan := make(chan model.OrphanedKey)
	errChan := make(chan error)
	close(orphansChan)
	close(errChan)

	store.EXPECT().OrphanedKeyStats(mock.Anything, mock.Anything).Return(&model.OrphanStats{}, nil).Maybe()
	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything).Return(orphansChan, errChan).Maybe()
	metrics.EXPECT().With("component", "orphan_recoverer").Return(metrics).Maybe()
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

func TestOrphanRecoverer_RecoversPanicEmitsMetricAndKeepsRunning(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	metrics := mocks.NewMockAggregatorMetricLabeler(t)

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

	metrics.EXPECT().With("component", "orphan_recoverer").Return(metrics).Maybe()
	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().IncrementPanics(mock.Anything).Times(1)

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:         true,
			IntervalSeconds: 1,
			MaxAgeHours:     24,
		},
	}

	recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_ = recoverer.Start(ctx)
		close(done)
	}()

	// Wait for the first scan (which panics) and the second scan (which succeeds)
	time.Sleep(1500 * time.Millisecond)

	// Service should still be running and healthy after recovering from panic
	require.NoError(t, recoverer.Ready())
	require.GreaterOrEqual(t, panicCount, 1, "panic should have occurred at least once")

	// Clean up - cancel and wait for goroutine to exit
	cancel()
	<-done
}
