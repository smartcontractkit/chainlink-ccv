package aggregation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/memory"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// MockQuorumValidator is a mock implementation of QuorumValidator for testing.
type MockQuorumValidator struct {
	mock.Mock
}

func (m *MockQuorumValidator) CheckQuorum(ctx context.Context, report *model.CommitAggregatedReport) (bool, error) {
	args := m.Called(ctx, report)
	return args.Bool(0), args.Error(1)
}

// MockAggregatorMonitoring is a mock implementation for testing.
type MockAggregatorMonitoring struct {
	mock.Mock
}

func (m *MockAggregatorMonitoring) Metrics() common.AggregatorMetricLabeler {
	args := m.Called()
	return args.Get(0).(common.AggregatorMetricLabeler)
}

// MockMetricLabeler is a mock implementation for testing.
type MockMetricLabeler struct {
	mock.Mock
}

func (m *MockMetricLabeler) IncrementPendingAggregationsChannelBuffer(ctx context.Context, count int) {
	m.Called(ctx, count)
}

func (m *MockMetricLabeler) DecrementPendingAggregationsChannelBuffer(ctx context.Context, count int) {
	m.Called(ctx, count)
}

func (m *MockMetricLabeler) IncrementCompletedAggregations(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockMetricLabeler) RecordTimeToAggregation(ctx context.Context, duration any) {
	m.Called(ctx, duration)
}

func TestShouldSkipAggregationDueToExistingQuorum(t *testing.T) {
	ctx := context.Background()
	messageID := model.MessageID{1, 2, 3}
	committeeID := model.CommitteeID("test-committee")

	t.Run("feature is disabled by default", func(t *testing.T) {
		storage := memory.NewInMemoryStorage()
		quorum := &MockQuorumValidator{}
		monitoring := &MockAggregatorMonitoring{}
		metricLabeler := &MockMetricLabeler{}

		monitoring.On("Metrics").Return(metricLabeler)
		metricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)
		metricLabeler.On("DecrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)

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
		quorum := &MockQuorumValidator{}
		monitoring := &MockAggregatorMonitoring{}
		metricLabeler := &MockMetricLabeler{}

		monitoring.On("Metrics").Return(metricLabeler)
		metricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)
		metricLabeler.On("DecrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)

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
		quorum := &MockQuorumValidator{}
		monitoring := &MockAggregatorMonitoring{}
		metricLabeler := &MockMetricLabeler{}

		monitoring.On("Metrics").Return(metricLabeler)
		metricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)
		metricLabeler.On("DecrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)

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
		quorum := &MockQuorumValidator{}
		monitoring := &MockAggregatorMonitoring{}
		metricLabeler := &MockMetricLabeler{}

		monitoring.On("Metrics").Return(metricLabeler)
		metricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)
		metricLabeler.On("DecrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)

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
		quorum := &MockQuorumValidator{}
		monitoring := &MockAggregatorMonitoring{}
		metricLabeler := &MockMetricLabeler{}

		monitoring.On("Metrics").Return(metricLabeler)
		metricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)
		metricLabeler.On("DecrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)

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
		quorum.On("CheckQuorum", ctx, existingReport).Return(true, nil)

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
		quorum := &MockQuorumValidator{}
		monitoring := &MockAggregatorMonitoring{}
		metricLabeler := &MockMetricLabeler{}

		monitoring.On("Metrics").Return(metricLabeler)
		metricLabeler.On("IncrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)
		metricLabeler.On("DecrementPendingAggregationsChannelBuffer", mock.Anything, mock.Anything)

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
		quorum.On("CheckQuorum", ctx, existingReport).Return(false, nil)

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
		quorum.AssertExpectations(t)
	})
}
