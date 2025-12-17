package aggregation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
)

func TestShouldSkipAggregationDueToExistingQuorum(t *testing.T) {
	ctx := context.Background()
	messageID := model.MessageID{1, 2, 3}

	t.Run("should not skip when aggregated store is nil", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		aggregator := NewCommitReportAggregator(
			store,
			nil,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)

		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when no existing report", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		aggStore := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByMessageID(ctx, messageID).Return(nil, nil)

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)

		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should skip when existing report meets quorum", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		aggStore := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		existingReport := &model.CommitAggregatedReport{
			MessageID:     messageID,
			Verifications: []*model.CommitVerificationRecord{},
		}

		aggStore.EXPECT().GetCommitAggregatedReportByMessageID(ctx, messageID).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(true, nil)

		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)

		require.NoError(t, err)
		assert.True(t, shouldSkip)
		quorum.AssertExpectations(t)
	})

	t.Run("should not skip when existing report does not meet quorum", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		aggStore := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
			},
		}

		existingReport := &model.CommitAggregatedReport{
			MessageID:     messageID,
			Verifications: []*model.CommitVerificationRecord{},
		}

		aggStore.EXPECT().GetCommitAggregatedReportByMessageID(ctx, messageID).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, nil)

		aggregator := NewCommitReportAggregator(
			store,
			aggStore,
			sink,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)

		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when GetCommitAggregatedReportByMessageID errors", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		aggStore := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCommitAggregatedReportByMessageID(ctx, messageID).Return(nil, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring)
		shouldSkip, err := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)
		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when quorum check errors", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		aggStore := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		existingReport := &model.CommitAggregatedReport{MessageID: messageID}
		aggStore.EXPECT().GetCommitAggregatedReportByMessageID(ctx, messageID).Return(existingReport, nil)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(store, aggStore, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring)
		shouldSkip, err := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)
		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})
}

func TestHealthCheck(t *testing.T) {
	cases := []struct {
		name           string
		pending        int
		capacity       int
		stopped        bool
		wantReadyError bool
		wantMsgPrefix  string
	}{
		{name: "healthy", pending: 0, capacity: 10, wantReadyError: false},
		{name: "high", pending: 9, capacity: 10, wantReadyError: false},
		{name: "full", pending: 10, capacity: 10, wantReadyError: false},
		{name: "stopped", pending: 0, capacity: 10, stopped: true, wantReadyError: true, wantMsgPrefix: "aggregation worker stopped"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := aggregation_mocks.NewMockCommitVerificationStore(t)
			sink := aggregation_mocks.NewMockSink(t)
			monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
			metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
			monitoring.EXPECT().Metrics().Return(metric).Maybe()

			config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: tc.capacity, BackgroundWorkerCount: 1}}
			a := NewCommitReportAggregator(store, nil, sink, aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

			for i := 0; i < tc.pending; i++ {
				a.aggregationKeyChan <- aggregationRequest{}
			}
			if tc.stopped {
				a.done = make(chan struct{})
				close(a.done)
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
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().IncrementPendingAggregationsChannelBuffer(mock.Anything, 1)

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 2, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(store, nil, sink, aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

		err := a.CheckAggregation([]byte{1}, "")
		require.NoError(t, err)
	})

	t.Run("returns error when channel full", func(t *testing.T) {
		store := aggregation_mocks.NewMockCommitVerificationStore(t)
		sink := aggregation_mocks.NewMockSink(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(store, nil, sink, aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

		// Fill buffer
		a.aggregationKeyChan <- aggregationRequest{}

		err := a.CheckAggregation([]byte{1}, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, common.ErrAggregationChannelFull)
	})
}

func TestCheckAggregationAndSubmitComplete(t *testing.T) {
	ctx := context.Background()
	msgID := model.MessageID{0x1}
	aggregationKey := "key"

	request := aggregationRequest{
		MessageID:      msgID,
		AggregationKey: aggregationKey,
	}

	t.Run("list error", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return(nil, errors.New("boom"))

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, aggregation_mocks.NewMockSink(t), aggregation_mocks.NewMockQuorumValidator(t), &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum error", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(false, errors.New("boom")).Maybe()

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, aggregation_mocks.NewMockSink(t), quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum met submits and records metrics", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(true, nil).Maybe()
		sink := aggregation_mocks.NewMockSink(t)
		sink.EXPECT().SubmitAggregatedReport(ctx, mock.Anything).Return(nil)

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().IncrementCompletedAggregations(ctx)
		metric.EXPECT().RecordTimeToAggregation(ctx, mock.Anything)

		a := NewCommitReportAggregator(storage, nil, sink, quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.NoError(t, err)
	})

	t.Run("quorum met submit error", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(true, nil).Maybe()
		sink := aggregation_mocks.NewMockSink(t)
		sink.EXPECT().SubmitAggregatedReport(ctx, mock.Anything).Return(errors.New("boom"))

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, sink, quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.Error(t, err)
	})

	t.Run("quorum not met", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByAggregationKey(ctx, msgID, aggregationKey).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(false, nil).Maybe()

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, aggregation_mocks.NewMockSink(t), quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, request)
		require.NoError(t, err)
	})
}

func TestHealthCheck_ReportsStoppedAfterContextCancellation(t *testing.T) {
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	sink := aggregation_mocks.NewMockSink(t)
	monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
	metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 1}}
	a := NewCommitReportAggregator(store, nil, sink, aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

	ctx, cancel := context.WithCancel(context.Background())
	a.StartBackground(ctx)

	require.NoError(t, a.Ready())

	cancel()
	time.Sleep(50 * time.Millisecond)

	err := a.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped")
}

func TestHealthCheck_RecoversPanicAndKeepsRunning(t *testing.T) {
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	sink := aggregation_mocks.NewMockSink(t)
	monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
	metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()
	metric.EXPECT().IncrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()
	metric.EXPECT().DecrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()

	panicCount := 0
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ model.MessageID, _ model.AggregationKey) {
			panicCount++
			if panicCount == 1 {
				panic("simulated panic in storage")
			}
		}).Return([]*model.CommitVerificationRecord{}, nil).Maybe()

	quorum := aggregation_mocks.NewMockQuorumValidator(t)
	quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 1}}
	a := NewCommitReportAggregator(store, nil, sink, quorum, config, logger.Sugared(logger.Test(t)), monitoring)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartBackground(ctx)

	require.NoError(t, a.Ready())

	// First request panics
	_ = a.CheckAggregation([]byte{1, 2, 3}, "test-key")
	time.Sleep(100 * time.Millisecond)

	// Still healthy after 1 panic (threshold is 3)
	require.NoError(t, a.Ready())

	// Second request succeeds, resetting the counter
	_ = a.CheckAggregation([]byte{4, 5, 6}, "test-key-2")
	time.Sleep(100 * time.Millisecond)

	require.NoError(t, a.Ready())
}

func TestHealthCheck_UnhealthyAfterConsecutivePanics(t *testing.T) {
	store := aggregation_mocks.NewMockCommitVerificationStore(t)
	sink := aggregation_mocks.NewMockSink(t)
	monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
	metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
	monitoring.EXPECT().Metrics().Return(metric).Maybe()
	metric.EXPECT().IncrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()
	metric.EXPECT().DecrementPendingAggregationsChannelBuffer(mock.Anything, 1).Maybe()

	panicCount := 0
	store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ model.MessageID, _ model.AggregationKey) {
			panicCount++
			panic("simulated consecutive panic")
		}).Maybe()

	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 1}}
	a := NewCommitReportAggregator(store, nil, sink, aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartBackground(ctx)

	require.NoError(t, a.Ready())

	// Send 3 requests that will all panic
	for i := 0; i < 3; i++ {
		_ = a.CheckAggregation([]byte{byte(i)}, fmt.Sprintf("key-%d", i))
		time.Sleep(100 * time.Millisecond)
	}

	// Should report unhealthy after 3 consecutive panics
	err := a.Ready()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consecutive panics")
	require.GreaterOrEqual(t, panicCount, 3, "should have panicked at least 3 times")
}

// helpers.
var _ = time.Duration(0)
