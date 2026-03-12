package aggregator

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var errScanFailed = errors.New("scan failed")

func TestOrphanRecoverer_HealthCheck_NotStarted(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	metrics := mocks.NewMockAggregatorMetricLabeler(t)

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:     true,
			Interval:    60 * time.Second,
			MaxAge:      24 * time.Hour,
			ScanTimeout: 4 * time.Minute,
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
	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything, mock.Anything).Return(orphansChan, errChan).Maybe()
	metrics.EXPECT().With("component", "orphan_recoverer").Return(metrics).Maybe()
	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:     true,
			Interval:    1 * time.Second,
			MaxAge:      24 * time.Hour,
			ScanTimeout: 4 * time.Minute,
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
	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything, mock.Anything).Return(orphansChan, errChan).Maybe()

	metrics.EXPECT().With("component", "orphan_recoverer").Return(metrics).Maybe()
	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().IncrementPanics(mock.Anything).Times(1)

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:     true,
			Interval:    1 * time.Second,
			MaxAge:      24 * time.Hour,
			ScanTimeout: 4 * time.Minute,
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

func TestOrphanRecoverer_HealthCheck_ReturnsErrorAfterConsecutiveScanFailures(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	metrics := mocks.NewMockAggregatorMetricLabeler(t)

	var listCallCount atomic.Int32
	store.EXPECT().OrphanedKeyStats(mock.Anything, mock.Anything).Return(&model.OrphanStats{}, nil).Maybe()
	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ time.Time, _ int) (<-chan model.OrphanedKey, <-chan error) {
			callNum := listCallCount.Add(1)
			errChan := make(chan error, 1)
			if callNum <= 4 {
				orphansChan := make(chan model.OrphanedKey)
				errChan <- errScanFailed
				close(errChan)
				return orphansChan, errChan
			}
			orphansChan := make(chan model.OrphanedKey)
			close(orphansChan)
			close(errChan)
			return orphansChan, errChan
		}).Maybe()

	metrics.EXPECT().With("component", "orphan_recoverer").Return(metrics).Maybe()
	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().IncrementOrphanRecoveryErrors(mock.Anything).Maybe()

	interval := 80 * time.Millisecond
	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:              true,
			Interval:             interval,
			MaxAge:               24 * time.Hour,
			ScanTimeout:          4 * time.Minute,
			MaxConsecutiveErrors: 3,
		},
	}

	recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = recoverer.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, recoverer.Ready(), "should be ready after start")

	require.Eventually(t, func() bool {
		err := recoverer.Ready()
		return err != nil
	}, 5*time.Second, 20*time.Millisecond, "Ready() should return error after 4 consecutive scan failures")

	err := recoverer.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "times in a row")
	assert.ErrorIs(t, err, errScanFailed)

	require.Eventually(t, func() bool {
		return recoverer.Ready() == nil
	}, 5*time.Second, 20*time.Millisecond, "Ready() should return nil again after a successful scan")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recoverer did not stop in time")
	}
}

func makeOrphanedKey(i int) model.OrphanedKey {
	return model.OrphanedKey{
		MessageID:      fmt.Appendf(nil, "msg-%06d", i),
		AggregationKey: fmt.Sprintf("key-%06d", i),
	}
}

func setupOrphanRecovererMocks(t *testing.T) (*mocks.MockCommitVerificationStore, *mocks.MockAggregationTriggerer, *mocks.MockAggregatorMetricLabeler) {
	t.Helper()
	store := mocks.NewMockCommitVerificationStore(t)
	agg := mocks.NewMockAggregationTriggerer(t)
	metrics := mocks.NewMockAggregatorMetricLabeler(t)

	store.EXPECT().OrphanedKeyStats(mock.Anything, mock.Anything).Return(&model.OrphanStats{}, nil).Maybe()
	metrics.EXPECT().With(mock.Anything, mock.Anything).Return(metrics).Maybe()
	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().RecordOrphanRecoveryDuration(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().IncrementOrphanRecoveryErrors(mock.Anything).Maybe()

	return store, agg, metrics
}

func makeOrphanChannel(count int) (<-chan model.OrphanedKey, <-chan error) {
	orphansChan := make(chan model.OrphanedKey, count)
	errChan := make(chan error, 1)
	for i := range count {
		orphansChan <- makeOrphanedKey(i)
	}
	close(orphansChan)
	// errChan is intentionally left open: in the real ListOrphanedKeys, errChan
	// is closed by the sender goroutine after orphansChan is drained. When both
	// channels are ready, Go's select picks randomly. Leaving errChan open
	// prevents a non-deterministic early exit so RecoverOrphans always drains
	// orphansChan first. The context cancellation in RecoverOrphans ensures no
	// goroutine leak despite errChan never being closed.
	return orphansChan, errChan
}

func TestOrphanRecoverer_RecoverOrphans_MaxOrphansPerScanEnforced(t *testing.T) {
	tests := []struct {
		name              string
		totalOrphans      int
		maxOrphansPerScan int
		wantProcessed     int
	}{
		{"zero_orphans_processes_none", 0, 10000, 0},
		{"under_cap_processes_all", 50, 10000, 50},
		{"at_cap_stops", 100, 100, 100},
		{"over_cap_stops_at_cap", 500, 100, 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, agg, metrics := setupOrphanRecovererMocks(t)

			orphansChan, errChan := makeOrphanChannel(tc.totalOrphans)
			store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything, mock.Anything).Return(orphansChan, errChan)

			var checkAggCount atomic.Int32
			agg.EXPECT().CheckAggregation(mock.Anything, mock.Anything, mock.Anything, model.OrphanRecoveryChannelKey, mock.Anything).
				RunAndReturn(func(_ context.Context, _ model.MessageID, _ model.AggregationKey, _ model.ChannelKey, _ time.Duration) error {
					checkAggCount.Add(1)
					return nil
				}).Maybe()

			config := &model.AggregatorConfig{
				OrphanRecovery: model.OrphanRecoveryConfig{
					Enabled:           true,
					Interval:          time.Hour,
					MaxAge:            24 * time.Hour,
					ScanTimeout:       4 * time.Minute,
					MaxOrphansPerScan: tc.maxOrphansPerScan,
				},
			}

			recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)
			err := recoverer.RecoverOrphans(context.Background())
			require.NoError(t, err)
			require.Equal(t, tc.wantProcessed, int(checkAggCount.Load()))
		})
	}
}

func TestOrphanRecoverer_RecoverOrphans_PassesConfiguredPageSize(t *testing.T) {
	store, agg, metrics := setupOrphanRecovererMocks(t)

	const expectedPageSize = 42
	orphansChan, errChan := makeOrphanChannel(0)

	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything, expectedPageSize).Return(orphansChan, errChan)

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:           true,
			Interval:          time.Hour,
			MaxAge:            24 * time.Hour,
			ScanTimeout:       4 * time.Minute,
			MaxOrphansPerScan: 10000,
			PageSize:          expectedPageSize,
		},
	}

	recoverer := NewOrphanRecoverer(store, agg, config, logger.Sugared(logger.Test(t)), metrics)
	err := recoverer.RecoverOrphans(context.Background())
	require.NoError(t, err)
}

func TestOrphanRecoverer_RecoverOrphans_ScanTimeoutCancelsLongScan(t *testing.T) {
	store, _, metrics := setupOrphanRecovererMocks(t)

	orphansChan := make(chan model.OrphanedKey)
	errChan := make(chan error, 1)

	store.EXPECT().ListOrphanedKeys(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, _ time.Time, _ int) (<-chan model.OrphanedKey, <-chan error) {
			go func() {
				defer close(orphansChan)
				defer close(errChan)
				for {
					select {
					case <-ctx.Done():
						return
					case <-time.After(10 * time.Millisecond):
					}
				}
			}()
			return orphansChan, errChan
		})

	scanTimeout := 100 * time.Millisecond
	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:           true,
			MaxAge:            24 * time.Hour,
			ScanTimeout:       scanTimeout,
			MaxOrphansPerScan: 10000,
		},
	}

	recoverer := NewOrphanRecoverer(store, nil, config, logger.Sugared(logger.Test(t)), metrics)
	start := time.Now()
	err := recoverer.RecoverOrphans(context.Background())
	duration := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, duration, 2*scanTimeout)
}
