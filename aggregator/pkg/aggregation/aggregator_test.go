package aggregation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/memory"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
)

func TestShouldSkipAggregationDueToExistingQuorum(t *testing.T) {
	ctx := context.Background()
	messageID := model.MessageID{1, 2, 3}

	t.Run("should not skip when aggregated store is nil", func(t *testing.T) {
		storage := memory.NewInMemoryStorage()
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
			storage,
			nil,
			storage,
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
		storage := memory.NewInMemoryStorage()
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
			storage,
			storage,
			storage,
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
		storage := memory.NewInMemoryStorage()
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

		err := storage.SubmitReport(ctx, existingReport)
		require.NoError(t, err)

		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(true, nil)

		aggregator := NewCommitReportAggregator(
			storage,
			storage,
			storage,
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
		storage := memory.NewInMemoryStorage()
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
			CommitteeID:   committeeID,
			Verifications: []*model.CommitVerificationRecord{},
		}

		err := storage.SubmitReport(ctx, existingReport)
		require.NoError(t, err)

		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, nil)

		aggregator := NewCommitReportAggregator(
			storage,
			storage,
			storage,
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)

		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when GetCCVData errors", func(t *testing.T) {
		aggStore := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCCVData(ctx, messageID).Return(nil, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(memory.NewInMemoryStorage(), aggStore, memory.NewInMemoryStorage(), quorum, config, logger.Sugared(logger.Test(t)), monitoring)
		shouldSkip, err := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)
		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when quorum check errors", func(t *testing.T) {
		storage := memory.NewInMemoryStorage()
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		existingReport := &model.CommitAggregatedReport{MessageID: messageID}
		err := storage.SubmitReport(ctx, existingReport)
		require.NoError(t, err)

		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(storage, storage, storage, quorum, config, logger.Sugared(logger.Test(t)), monitoring)
		shouldSkip, err := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID)
		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})
}

func TestHealthCheck(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name          string
		pending       int
		capacity      int
		stopped       bool
		wantStatus    common.HealthStatus
		wantMsgPrefix string
	}{
		{name: "healthy", pending: 0, capacity: 10, wantStatus: common.HealthStatusHealthy, wantMsgPrefix: "aggregation queue healthy"},
		{name: "high", pending: 9, capacity: 10, wantStatus: common.HealthStatusDegraded, wantMsgPrefix: "aggregation queue high"},
		{name: "full", pending: 10, capacity: 10, wantStatus: common.HealthStatusDegraded, wantMsgPrefix: "aggregation queue full"},
		{name: "stopped", pending: 0, capacity: 10, stopped: true, wantStatus: common.HealthStatusUnhealthy, wantMsgPrefix: "aggregation worker stopped"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
			metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
			monitoring.EXPECT().Metrics().Return(metric).Maybe()

			config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: tc.capacity, BackgroundWorkerCount: 1}}
			a := NewCommitReportAggregator(memory.NewInMemoryStorage(), nil, memory.NewInMemoryStorage(), aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

			for i := 0; i < tc.pending; i++ {
				a.aggregationKeyChan <- aggregationRequest{}
			}
			if tc.stopped {
				a.done = make(chan struct{})
				close(a.done)
			}

			h := a.HealthCheck(ctx)
			assert.Equal(t, tc.wantStatus, h.Status)
			assert.Equal(t, tc.wantMsgPrefix, h.Message)
		})
	}
}

func TestCheckAggregation_EnqueueAndFull(t *testing.T) {
	t.Run("enqueues and records metric", func(t *testing.T) {
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().IncrementPendingAggregationsChannelBuffer(mock.Anything, 1)

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 2, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(memory.NewInMemoryStorage(), nil, memory.NewInMemoryStorage(), aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

		err := a.CheckAggregation([]byte{1}, "")
		require.NoError(t, err)
	})

	t.Run("returns error when channel full", func(t *testing.T) {
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(memory.NewInMemoryStorage(), nil, memory.NewInMemoryStorage(), aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

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
		sink.EXPECT().SubmitReport(ctx, mock.Anything).Return(nil)

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
		sink.EXPECT().SubmitReport(ctx, mock.Anything).Return(errors.New("boom"))

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

func TestDeduplicateVerificationsByParticipant(t *testing.T) {
	v1 := &model.CommitVerificationRecord{IdentifierSigner: &model.IdentifierSigner{ParticipantID: "A"}, Timestamp: time.UnixMilli(1)}
	v2 := &model.CommitVerificationRecord{IdentifierSigner: &model.IdentifierSigner{ParticipantID: "A"}, Timestamp: time.UnixMilli(2)}
	v3 := &model.CommitVerificationRecord{IdentifierSigner: &model.IdentifierSigner{ParticipantID: "B"}, Timestamp: time.UnixMilli(3)}
	vNo := &model.CommitVerificationRecord{Timestamp: time.UnixMilli(5)}

	got := deduplicateVerificationsByParticipant([]*model.CommitVerificationRecord{v1, v2, v3, vNo})
	assert.Len(t, got, 2)
	var aFound, bFound bool
	for _, v := range got {
		if v.IdentifierSigner.ParticipantID == "A" {
			aFound = true
			assert.True(t, v.GetTimestamp().Equal(time.UnixMilli(2)))
		}
		if v.IdentifierSigner.ParticipantID == "B" {
			bFound = true
			assert.True(t, v.GetTimestamp().Equal(time.UnixMilli(3)))
		}
	}
	assert.True(t, aFound && bFound)
}

// helpers.
var _ = time.Duration(0)
