package aggregation

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/memory"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestShouldSkipAggregationDueToExistingQuorum(t *testing.T) {
	ctx := context.Background()
	messageID := model.MessageID{1, 2, 3}
	committeeID := model.CommitteeID("test-committee")

	t.Run("feature is disabled by default", func(t *testing.T) {
		storage := memory.NewInMemoryStorage()
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:     10,
				BackgroundWorkerCount: 1,
				// Don't set EnableAggregationAfterQuorum - let defaults apply (false)
			},
		}

		// Apply defaults to verify it's disabled by default
		config.SetDefaults()

		aggregator := NewCommitReportAggregator(
			storage,
			storage, // storage also implements CommitVerificationAggregatedStore
			storage, // storage also implements Sink
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		) // Verify the feature is disabled by default (no reaggregation after quorum)
		assert.False(t, aggregator.enableAggregationAfterQuorum, "EnableAggregationAfterQuorum should be disabled by default")

		// Test the functionality works with defaults
		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)

		require.NoError(t, err)
		assert.False(t, shouldSkip) // No existing report, so should not skip
	})

	t.Run("should not skip when aggregated store is nil", func(t *testing.T) {
		storage := memory.NewInMemoryStorage()
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:            10,
				BackgroundWorkerCount:        1,
				EnableAggregationAfterQuorum: false, // Feature disabled (default)
			},
		}

		aggregator := NewCommitReportAggregator(
			storage,
			nil,     // No aggregated store - should fall back gracefully
			storage, // storage implements Sink
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)

		require.NoError(t, err)
		assert.False(t, shouldSkip) // Should not skip when aggregated store is nil
	})

	t.Run("should skip when reaggregation is enabled", func(t *testing.T) {
		storage := memory.NewInMemoryStorage()
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		config := &model.AggregatorConfig{
			Aggregation: model.AggregationConfig{
				ChannelBufferSize:            10,
				BackgroundWorkerCount:        1,
				EnableAggregationAfterQuorum: true, // Feature enabled (allows reaggregation)
			},
		}

		aggregator := NewCommitReportAggregator(
			storage,
			storage, // storage also implements CommitVerificationAggregatedStore
			storage, // storage also implements Sink
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)

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
				ChannelBufferSize:            10,
				BackgroundWorkerCount:        1,
				EnableAggregationAfterQuorum: false, // Feature disabled (default)
			},
		}

		aggregator := NewCommitReportAggregator(
			storage,
			storage, // storage also implements CommitVerificationAggregatedStore
			storage, // storage also implements Sink
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)

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
				ChannelBufferSize:            10,
				BackgroundWorkerCount:        1,
				EnableAggregationAfterQuorum: false, // Feature disabled
			},
		}

		// Create an existing aggregated report
		existingReport := &model.CommitAggregatedReport{
			MessageID:     messageID,
			CommitteeID:   committeeID,
			Verifications: []*model.CommitVerificationRecord{}, // Empty for simplicity
		}

		// Store the existing report
		err := storage.SubmitReport(ctx, existingReport)
		require.NoError(t, err)

		// Mock quorum check to return true (quorum met)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(true, nil)

		aggregator := NewCommitReportAggregator(
			storage,
			storage, // storage also implements CommitVerificationAggregatedStore
			storage, // storage also implements Sink
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)

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
				ChannelBufferSize:            10,
				BackgroundWorkerCount:        1,
				EnableAggregationAfterQuorum: false, // Feature disabled
			},
		}

		// Create an existing aggregated report
		existingReport := &model.CommitAggregatedReport{
			MessageID:     messageID,
			CommitteeID:   committeeID,
			Verifications: []*model.CommitVerificationRecord{}, // Empty for simplicity
		}

		// Store the existing report
		err := storage.SubmitReport(ctx, existingReport)
		require.NoError(t, err)

		// Mock quorum check to return false (quorum not met)
		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, nil)

		aggregator := NewCommitReportAggregator(
			storage,
			storage, // storage also implements CommitVerificationAggregatedStore
			storage, // storage also implements Sink
			quorum,
			config,
			logger.Sugared(logger.Test(t)),
			monitoring,
		)

		shouldSkip, err := aggregator.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)

		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when GetCCVData errors", func(t *testing.T) {
		aggStore := aggregation_mocks.NewMockCommitVerificationAggregatedStore(t)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()
		aggStore.EXPECT().GetCCVData(ctx, messageID, string(committeeID)).Return(nil, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(memory.NewInMemoryStorage(), aggStore, memory.NewInMemoryStorage(), quorum, config, logger.Sugared(logger.Test(t)), monitoring)
		shouldSkip, err := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)
		require.NoError(t, err)
		assert.False(t, shouldSkip)
	})

	t.Run("should not skip when quorum check errors", func(t *testing.T) {
		storage := memory.NewInMemoryStorage()
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metricLabeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metricLabeler).Maybe()

		existingReport := &model.CommitAggregatedReport{MessageID: messageID, CommitteeID: committeeID}
		err := storage.SubmitReport(ctx, existingReport)
		require.NoError(t, err)

		quorum.EXPECT().CheckQuorum(ctx, existingReport).Return(false, errors.New("boom"))

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(storage, storage, storage, quorum, config, logger.Sugared(logger.Test(t)), monitoring)
		shouldSkip, err := a.shouldSkipAggregationDueToExistingQuorum(ctx, messageID, committeeID)
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
				a.messageIDChan <- aggregationRequest{}
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

		err := a.CheckAggregation([]byte{1}, model.CommitteeID("c"))
		require.NoError(t, err)
	})

	t.Run("returns error when channel full", func(t *testing.T) {
		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1}}
		a := NewCommitReportAggregator(memory.NewInMemoryStorage(), nil, memory.NewInMemoryStorage(), aggregation_mocks.NewMockQuorumValidator(t), config, logger.Sugared(logger.Test(t)), monitoring)

		// Fill buffer
		a.messageIDChan <- aggregationRequest{}

		err := a.CheckAggregation([]byte{1}, model.CommitteeID("c"))
		require.Error(t, err)
		assert.ErrorIs(t, err, common.ErrAggregationChannelFull)
	})
}

func TestCheckAggregationAndSubmitComplete(t *testing.T) {
	ctx := context.Background()
	msgID := model.MessageID{0x1}
	committeeID := model.CommitteeID("committee")

	t.Run("list error", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByMessageID(ctx, msgID, string(committeeID)).Return(nil, errors.New("boom"))

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, aggregation_mocks.NewMockSink(t), aggregation_mocks.NewMockQuorumValidator(t), &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1, EnableAggregationAfterQuorum: true}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, msgID, committeeID)
		require.Error(t, err)
	})

	t.Run("quorum error", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByMessageID(ctx, msgID, string(committeeID)).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(false, errors.New("boom")).Maybe()

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, aggregation_mocks.NewMockSink(t), quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1, EnableAggregationAfterQuorum: true}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, msgID, committeeID)
		require.Error(t, err)
	})

	t.Run("quorum met submits and records metrics", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByMessageID(ctx, msgID, string(committeeID)).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(true, nil).Maybe()
		sink := aggregation_mocks.NewMockSink(t)
		sink.EXPECT().SubmitReport(ctx, mock.Anything).Return(nil)

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()
		metric.EXPECT().IncrementCompletedAggregations(ctx)
		metric.EXPECT().RecordTimeToAggregation(ctx, mock.Anything)

		a := NewCommitReportAggregator(storage, nil, sink, quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1, EnableAggregationAfterQuorum: true}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, msgID, committeeID)
		require.NoError(t, err)
	})

	t.Run("quorum met submit error", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByMessageID(ctx, msgID, string(committeeID)).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(true, nil).Maybe()
		sink := aggregation_mocks.NewMockSink(t)
		sink.EXPECT().SubmitReport(ctx, mock.Anything).Return(errors.New("boom"))

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, sink, quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1, EnableAggregationAfterQuorum: true}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, msgID, committeeID)
		require.Error(t, err)
	})

	t.Run("quorum not met", func(t *testing.T) {
		storage := aggregation_mocks.NewMockCommitVerificationStore(t)
		storage.EXPECT().ListCommitVerificationByMessageID(ctx, msgID, string(committeeID)).Return([]*model.CommitVerificationRecord{}, nil)
		quorum := aggregation_mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(ctx, mock.Anything).Return(false, nil).Maybe()

		monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)
		metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		a := NewCommitReportAggregator(storage, nil, aggregation_mocks.NewMockSink(t), quorum, &model.AggregatorConfig{Aggregation: model.AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1, EnableAggregationAfterQuorum: true}}, logger.Sugared(logger.Test(t)), monitoring)
		_, err := a.checkAggregationAndSubmitComplete(ctx, msgID, committeeID)
		require.NoError(t, err)
	})
}

func TestDeduplicateVerificationsByParticipant(t *testing.T) {
	v1 := &model.CommitVerificationRecord{IdentifierSigner: &model.IdentifierSigner{Signer: model.Signer{ParticipantID: "A"}}, MessageWithCCVNodeData: pb.MessageWithCCVNodeData{Timestamp: 1}}
	v2 := &model.CommitVerificationRecord{IdentifierSigner: &model.IdentifierSigner{Signer: model.Signer{ParticipantID: "A"}}, MessageWithCCVNodeData: pb.MessageWithCCVNodeData{Timestamp: 2}}
	v3 := &model.CommitVerificationRecord{IdentifierSigner: &model.IdentifierSigner{Signer: model.Signer{ParticipantID: "B"}}, MessageWithCCVNodeData: pb.MessageWithCCVNodeData{Timestamp: 3}}
	vNo := &model.CommitVerificationRecord{MessageWithCCVNodeData: pb.MessageWithCCVNodeData{Timestamp: 5}}

	got := deduplicateVerificationsByParticipant([]*model.CommitVerificationRecord{v1, v2, v3, vNo})
	assert.Len(t, got, 2)
	var aFound, bFound bool
	for _, v := range got {
		if v.IdentifierSigner.ParticipantID == "A" {
			aFound = true
			assert.Equal(t, int64(2), v.GetTimestamp())
		}
		if v.IdentifierSigner.ParticipantID == "B" {
			bFound = true
			assert.Equal(t, int64(3), v.GetTimestamp())
		}
	}
	assert.True(t, aFound && bFound)
}

// helpers
var _ = time.Duration(0)
