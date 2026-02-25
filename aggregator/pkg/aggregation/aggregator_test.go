package aggregation

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestShouldSkipAggregationDueToExistingQuorum(t *testing.T) {
	messageID := model.MessageID{1, 2, 3}
	aggregationKey := model.AggregationKey("test-agg-key")

	t.Run("should not skip when aggregated store is nil", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		aggregator := NewCommitReportAggregator(
			store,
			nil,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			channelManager,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when no existing report", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(nil, common.ErrNotFound)

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			channelManager,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should skip when existing report meets quorum", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		existingReport := &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggregationKey,
			Verifications:  []*model.CommitVerificationRecord{},
		}

		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(true, nil)

		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			channelManager,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.True(t, shouldSkip)
		quorum.AssertExpectations(t)
	})

	t.Run("should not skip when existing report does not meet quorum", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		existingReport := &model.CommitAggregatedReport{
			MessageID:      messageID,
			AggregationKey: aggregationKey,
			Verifications:  []*model.CommitVerificationRecord{},
		}

		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, nil)

		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
			channelManager,
		)

		shouldSkip := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when GetCommitAggregatedReportByAggregationKey errors", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(nil, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		shouldSkip := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when quorum check errors", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		existingReport := &model.CommitAggregatedReport{MessageID: messageID, AggregationKey: aggregationKey}
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		shouldSkip := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when no report exists for requested aggregation key", func(t *testing.T) {
		ctx := t.Context()
		store := mocks.NewMockCommitVerificationStore(t)
		aggStore := mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := mocks.NewMockSink(t)
		quorum := mocks.NewMockQuorumValidator(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByAggregationKey(ctx, messageID, aggregationKey).Return(nil, common.ErrNotFound)

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		shouldSkip := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, aggregationKey)
		assert.False(t, shouldSkip)
	})
}

func TestHealthCheck(t *testing.T) {
	cases := []struct {
		name           string
		pending        int
		capacity       int
		stopped        bool
		notStarted     bool
		wantReadyError bool
		wantMsgPrefix  string
	}{
		{name: "healthy", pending: 0, capacity: 10, wantReadyError: false},
		{name: "high", pending: 9, capacity: 10, wantReadyError: false},
		{name: "full", pending: 10, capacity: 10, wantReadyError: false},
		{name: "stopped", pending: 0, capacity: 10, stopped: true, wantReadyError: true, wantMsgPrefix: "aggregation worker stopped"},
		{name: "not_started", pending: 0, capacity: 10, notStarted: true, wantReadyError: true, wantMsgPrefix: "aggregation worker not started"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := mocks.NewMockCommitVerificationStore(t)
			sink := mocks.NewMockSink(t)
			monitoring := mocks.NewMockAggregatorMonitoring(t)
			metric := mocks.NewMockAggregatorMetricLabeler(t)
			monitoring.EXPECT().Metrics().Return(metric).Maybe()

			config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: tc.capacity, BackgroundWorkerCount: 1}}
			channelManager := NewChannelManager([]model.ChannelKey{"test-client"}, config.Aggregation.ChannelBufferSize)
			a := NewCommitReportAggregator(store, nil, sink, mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, channelManager)

			for i := 0; i < tc.pending; i++ {
				_ = channelManager.Enqueue(t.Context(), "test-client", aggregationRequest{}, time.Millisecond)
			}
			if tc.stopped {
				a.done = make(chan struct{})
				close(a.done)
			} else if !tc.notStarted {
				a.done = make(chan struct{})
			}

			err := a.Ready()
			if tc.wantReadyError {
				assert.Error(t, err)
				assert.Equal(t, tc.wantMsgPrefix, err.Error())
			}
		})
	}
}

func TestCheckAggregation_EnqueueAndFull(t *testing.T) {
	t.Run("enqueues and records metric", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()
		metric.EXPECT().IncrementPendingAggregationsChannelBuffer(mock.Anything, 1)

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 2, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{"test-client"}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(store, nil, sink, mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, channelManager)

		err := a.CheckAggregation(t.Context(), []byte{1}, "test-key", "test-client", time.Millisecond)
		require.NoError(t, err)
	})

	t.Run("returns error when channel full", func(t *testing.T) {
		store := mocks.NewMockCommitVerificationStore(t)
		sink := mocks.NewMockSink(t)
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{"test-client"}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(store, nil, sink, mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, channelManager)

		_ = channelManager.Enqueue(t.Context(), "test-client", aggregationRequest{}, time.Millisecond)

		err := a.CheckAggregation(t.Context(), []byte{1}, "test-key", "test-client", time.Millisecond)
		require.Error(t, err)
		assert.ErrorIs(t, err, common.ErrAggregationChannelFull)
	})
}

func TestCheckAggregationAndSubmitComplete(t *testing.T) {
	ctx := t.Context()
	msgID := model.MessageID{0x1}
	aggregationKey := "key"

	request := aggregationRequest{
		MessageID:      msgID,
		AggregationKey: aggregationKey,
	}

	t.Run("list error", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return(nil, errors.New("boom"))

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(storage, nil, mocks.NewMockSink(t), mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum error", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(false, errors.New("boom")).Maybe()

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(storage, nil, mocks.NewMockSink(t), quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum met submits and records metrics", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(true, nil).Maybe()
		sink := mocks.NewMockSink(t)
		sink.EXPECT().SubmitAggregatedReport(ctx, mock.Anything).Return(nil)

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().With("component", "aggregator_worker").Return(metric).Maybe()
		metric.EXPECT().IncrementCompletedAggregations(ctx)
		metric.EXPECT().RecordTimeToAggregation(ctx, mock.Anything)

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(storage, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.NoError(t, err)
	})

	t.Run("quorum met submit error", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(true, nil).Maybe()
		sink := mocks.NewMockSink(t)
		sink.EXPECT().SubmitAggregatedReport(ctx, mock.Anything).Return(errors.New("boom"))

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(storage, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum not met", func(t *testing.T) {
		storage := mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(false, nil).Maybe()

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
		a := NewCommitReportAggregator(storage, nil, mocks.NewMockSink(t), quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)
		err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.NoError(t, err)
	})
}

func TestHealthCheck_ReportsStoppedAfterContextCancellation(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	sink := mocks.NewMockSink(t)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 1}}
	channelManager := NewChannelManager([]model.ChannelKey{}, config.Aggregation.ChannelBufferSize)
	a := NewCommitReportAggregator(store, nil, sink, mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring, channelManager)

	ctx, cancel := context.WithCancel(t.Context())
	a.StartBackground(ctx)

	require.NoError(t, a.Ready())

	cancel()
	time.Sleep(50 * time.Millisecond)

	err := a.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped")
}

func TestHealthCheck_RecoversPanicEmitsMetricAndKeepsRunning(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	sink := mocks.NewMockSink(t)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()
	metric.EXPECT().IncrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()
	metric.EXPECT().DecrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()
	metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()
	metric.EXPECT().IncrementPanics(mock.Anything).Times(1)

	panicCount := 0
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ model.MessageID, _ model.AggregationKey) {
			panicCount++
			if panicCount == 1 {
				panic("simulated panic in storage")
			}
		}).Return([]*model.CommitVerificationRecord{}, nil).Maybe()

	quorum := mocks.NewMockQuorumValidator(t)
	quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 1}}
	channelManager := NewChannelManager([]model.ChannelKey{"test-client"}, config.Aggregation.ChannelBufferSize)
	a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)

	ctx := t.Context()
	a.StartBackground(ctx)

	require.NoError(t, a.Ready())

	// First request panics
	_ = a.CheckAggregation(ctx, []byte{1, 2, 3}, "test-key", "test-client", time.Millisecond)
	time.Sleep(100 * time.Millisecond)

	// Still healthy after panic - we now emit metrics instead of tracking consecutive panics
	require.NoError(t, a.Ready())

	// Second request succeeds
	_ = a.CheckAggregation(ctx, []byte{4, 5, 6}, "test-key-2", "test-client", time.Millisecond)
	time.Sleep(100 * time.Millisecond)

	require.NoError(t, a.Ready())
}

func TestHealthCheck_ReturnsErrorAfterConsecutiveWorkerFailures(t *testing.T) {
	store := mocks.NewMockCommitVerificationStore(t)
	sink := mocks.NewMockSink(t)
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()
	metric.EXPECT().IncrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()
	metric.EXPECT().DecrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()
	metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()

	var listCallCount atomic.Int32
	storageErr := errors.New("storage error")
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ model.MessageID, _ model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
			callNum := listCallCount.Add(1)
			if callNum <= 3 {
				return nil, storageErr
			}
			return []*model.CommitVerificationRecord{}, nil
		}).Maybe()

	quorum := mocks.NewMockQuorumValidator(t)
	quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

	config := &model.AggregatorConfig{
		Aggregation: model.AggregationConfig{
			ChannelBufferSize:     10,
			BackgroundWorkerCount: 1,
			MaxConsecutiveErrors:  3,
		},
	}
	channelManager := NewChannelManager([]model.ChannelKey{"test-client"}, config.Aggregation.ChannelBufferSize)
	a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring, channelManager)

	ctx := t.Context()
	a.StartBackground(ctx)

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, a.Ready(), "should be ready after start")

	_ = a.CheckAggregation(ctx, []byte{1}, "key-1", "test-client", time.Millisecond)
	_ = a.CheckAggregation(ctx, []byte{2}, "key-2", "test-client", time.Millisecond)
	_ = a.CheckAggregation(ctx, []byte{3}, "key-3", "test-client", time.Millisecond)

	require.Eventually(t, func() bool {
		err := a.Ready()
		return err != nil
	}, 5*time.Second, 20*time.Millisecond, "Ready() should return error after 3 consecutive worker failures")

	err := a.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "times in a row")

	_ = a.CheckAggregation(ctx, []byte{4}, "key-4", "test-client", time.Millisecond)

	require.Eventually(t, func() bool {
		return a.Ready() == nil
	}, 5*time.Second, 20*time.Millisecond, "Ready() should return nil again after a successful aggregation")
}
