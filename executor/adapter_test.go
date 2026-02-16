package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// MockIndexerClient is a mock implementation of IndexerClientInterface for testing
type MockIndexerClient struct {
	mock.Mock
}

func (m *MockIndexerClient) Health(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockIndexerClient) VerifierResults(ctx context.Context, queryData v1.VerifierResultsInput) (int, v1.VerifierResultsResponse, error) {
	args := m.Called(ctx, queryData)
	return args.Int(0), args.Get(1).(v1.VerifierResultsResponse), args.Error(2)
}

func (m *MockIndexerClient) Messages(ctx context.Context, queryData v1.MessagesInput) (int, v1.MessagesResponse, error) {
	args := m.Called(ctx, queryData)
	return args.Int(0), args.Get(1).(v1.MessagesResponse), args.Error(2)
}

func (m *MockIndexerClient) VerifierResultsByMessageID(ctx context.Context, queryData v1.VerifierResultsByMessageIDInput) (int, v1.VerifierResultsByMessageIDResponse, error) {
	args := m.Called(ctx, queryData)
	return args.Int(0), args.Get(1).(v1.VerifierResultsByMessageIDResponse), args.Error(2)
}

// MockMonitoring is a mock implementation of Monitoring interface
type MockMonitoring struct {
	mock.Mock
}

func (m *MockMonitoring) Metrics() MetricLabeler {
	args := m.Called()
	return args.Get(0).(MetricLabeler)
}

// MockMetricLabeler is a mock implementation of MetricLabeler interface
type MockMetricLabeler struct {
	mock.Mock
}

func (m *MockMetricLabeler) With(keyValues ...string) MetricLabeler {
	args := m.Called(keyValues)
	return args.Get(0).(MetricLabeler)
}

func (m *MockMetricLabeler) RecordMessageExecutionLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector) {
	m.Called(ctx, duration, destChainSelector)
}

func (m *MockMetricLabeler) IncrementMessagesProcessed(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockMetricLabeler) IncrementMessagesProcessingFailed(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockMetricLabeler) IncrementCCVInfoCacheHits(ctx context.Context, destChainSelector protocol.ChainSelector) {
	m.Called(ctx, destChainSelector)
}

func (m *MockMetricLabeler) IncrementCCVInfoCacheMisses(ctx context.Context, destChainSelector protocol.ChainSelector) {
	m.Called(ctx, destChainSelector)
}

func (m *MockMetricLabeler) RecordOfframpGetCCVsForMessageLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector) {
	m.Called(ctx, duration, destChainSelector)
}

func (m *MockMetricLabeler) IncrementOfframpGetCCVsForMessageFailure(ctx context.Context, destChainSelector protocol.ChainSelector) {
	m.Called(ctx, destChainSelector)
}

func (m *MockMetricLabeler) IncrementExpiredMessages(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockMetricLabeler) IncrementAlreadyExecutedMessages(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockMetricLabeler) RecordMessageHeapSize(ctx context.Context, size int64) {
	m.Called(ctx, size)
}

func (m *MockMetricLabeler) IncrementHeartbeatSuccess(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockMetricLabeler) IncrementHeartbeatFailure(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockMetricLabeler) SetLastHeartbeatTimestamp(ctx context.Context, timestamp int64) {
	m.Called(ctx, timestamp)
}

func TestGetVerifierResults_PrimarySuccess(t *testing.T) {
	tests := []struct {
		name           string
		primaryStatus  int
		primaryErr     error
		alternateStatus int
		alternateErr   error
		expectedResults int
		expectError    bool
	}{
		{
			name:           "Primary returns 200, use primary",
			primaryStatus:  200,
			primaryErr:     nil,
			alternateStatus: 200,
			alternateErr:   nil,
			expectedResults: 2,
			expectError:    false,
		},
		{
			name:           "Primary returns 404, use primary (even though error)",
			primaryStatus:  404,
			primaryErr:     errors.New("not found"),
			alternateStatus: 200,
			alternateErr:   nil,
			expectedResults: 0,
			expectError:    true,
		},
		{
			name:           "Primary returns 500, use primary",
			primaryStatus:  500,
			primaryErr:     errors.New("server error"),
			alternateStatus: 200,
			alternateErr:   nil,
			expectedResults: 0,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			messageID := protocol.Bytes32{}

			// Setup mocks
			primaryClient := new(MockIndexerClient)
			alternateClient := new(MockIndexerClient)
			monitoring := new(MockMonitoring)
			metrics := new(MockMetricLabeler)

			monitoring.On("Metrics").Return(metrics)

			// Setup primary response
			primaryResp := v1.VerifierResultsByMessageIDResponse{
				Results: []common.VerifierResultWithMetadata{
					{VerifierResult: protocol.VerifierResult{}},
					{VerifierResult: protocol.VerifierResult{}},
				},
			}
			if tt.primaryErr != nil {
				primaryResp = v1.VerifierResultsByMessageIDResponse{}
			}

			primaryClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(tt.primaryStatus, primaryResp, tt.primaryErr)

			// Setup alternate response (should not be used)
			alternateResp := v1.VerifierResultsByMessageIDResponse{
				Results: []common.VerifierResultWithMetadata{
					{VerifierResult: protocol.VerifierResult{}},
				},
			}
			alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(tt.alternateStatus, alternateResp, tt.alternateErr)

			if tt.expectError {
				metrics.On("IncrementHeartbeatFailure", ctx).Return()
			} else {
				metrics.On("IncrementHeartbeatSuccess", ctx).Return()
				metrics.On("SetLastHeartbeatTimestamp", ctx, mock.AnythingOfType("int64")).Return()
			}

			// Create adapter
			lggr, _ := logger.New()
			adapter := &IndexerReaderAdapter{
				clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
				monitoring: monitoring,
				lggr:       lggr,
			}

			// Execute
			results, err := adapter.GetVerifierResults(ctx, messageID)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, results, tt.expectedResults)
			}

			primaryClient.AssertExpectations(t)
			alternateClient.AssertExpectations(t)
			monitoring.AssertExpectations(t)
			metrics.AssertExpectations(t)
		})
	}
}

func TestGetVerifierResults_PrimaryUnreachableHealthy(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	primaryClient := new(MockIndexerClient)
	alternateClient := new(MockIndexerClient)
	monitoring := new(MockMonitoring)
	metrics := new(MockMetricLabeler)

	monitoring.On("Metrics").Return(metrics)

	// Primary returns status 0 (unreachable)
	primaryClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	// But health check passes
	primaryClient.On("Health", mock.Anything).Return(nil)

	// Alternate should be called but not used
	alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
		},
	}, nil)

	metrics.On("IncrementHeartbeatFailure", ctx).Return()

	// Create adapter
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring,
		lggr:       lggr,
	}

	// Execute - should use primary despite status 0 because health check passes
	_, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should return primary's error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")

	primaryClient.AssertExpectations(t)
	alternateClient.AssertExpectations(t)
	monitoring.AssertExpectations(t)
	metrics.AssertExpectations(t)
}

func TestGetVerifierResults_PrimaryUnreachableUnhealthyFailover(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	primaryClient := new(MockIndexerClient)
	alternateClient := new(MockIndexerClient)
	monitoring := new(MockMonitoring)
	metrics := new(MockMetricLabeler)

	monitoring.On("Metrics").Return(metrics)

	// Primary returns status 0 (unreachable)
	primaryClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	// And health check fails
	primaryClient.On("Health", mock.Anything).Return(errors.New("unhealthy"))

	// Alternate succeeds
	alternateResp := v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
			{VerifierResult: protocol.VerifierResult{}},
		},
	}
	alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, alternateResp, nil)

	metrics.On("IncrementHeartbeatSuccess", ctx).Return()
	metrics.On("SetLastHeartbeatTimestamp", ctx, mock.AnythingOfType("int64")).Return()

	// Create adapter
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring,
		lggr:       lggr,
	}

	// Execute - should use alternate
	results, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should succeed with alternate's results
	require.NoError(t, err)
	assert.Len(t, results, 2)

	primaryClient.AssertExpectations(t)
	alternateClient.AssertExpectations(t)
	monitoring.AssertExpectations(t)
	metrics.AssertExpectations(t)
}

func TestGetVerifierResults_AllClientsUnreachable(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	primaryClient := new(MockIndexerClient)
	alternateClient := new(MockIndexerClient)
	monitoring := new(MockMonitoring)
	metrics := new(MockMetricLabeler)

	monitoring.On("Metrics").Return(metrics)

	// Primary returns status 0 (unreachable) and unhealthy
	primaryClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	primaryClient.On("Health", mock.Anything).Return(errors.New("unhealthy"))

	// Alternate also returns status 0
	alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection timeout"))

	metrics.On("IncrementHeartbeatFailure", ctx).Return()

	// Create adapter
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring,
		lggr:       lggr,
	}

	// Execute
	_, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should fail with "all clients failed" error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all indexer clients failed")

	primaryClient.AssertExpectations(t)
	alternateClient.AssertExpectations(t)
	monitoring.AssertExpectations(t)
	metrics.AssertExpectations(t)
}

func TestReadMessages_PrimarySuccess(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	primaryClient := new(MockIndexerClient)
	alternateClient := new(MockIndexerClient)
	monitoring := new(MockMonitoring)
	metrics := new(MockMetricLabeler)

	monitoring.On("Metrics").Return(metrics)

	// Primary succeeds
	primaryResp := v1.MessagesResponse{
		Messages: map[string]common.MessageWithMetadata{
			"msg1": {},
			"msg2": {},
		},
	}
	primaryClient.On("Messages", ctx, queryData).Return(200, primaryResp, nil)

	// Alternate should be called but not used
	alternateClient.On("Messages", ctx, queryData).Return(200, v1.MessagesResponse{Messages: map[string]common.MessageWithMetadata{}}, nil)

	metrics.On("IncrementHeartbeatSuccess", ctx).Return()
	metrics.On("SetLastHeartbeatTimestamp", ctx, mock.AnythingOfType("int64")).Return()

	// Create adapter
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring,
		lggr:       lggr,
	}

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)

	primaryClient.AssertExpectations(t)
	alternateClient.AssertExpectations(t)
	monitoring.AssertExpectations(t)
	metrics.AssertExpectations(t)
}

func TestReadMessages_PrimaryUnreachableFailover(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	primaryClient := new(MockIndexerClient)
	alternateClient := new(MockIndexerClient)
	monitoring := new(MockMonitoring)
	metrics := new(MockMetricLabeler)

	monitoring.On("Metrics").Return(metrics)

	// Primary returns status 0 and unhealthy
	primaryClient.On("Messages", ctx, queryData).Return(0, v1.MessagesResponse{}, errors.New("connection refused"))
	primaryClient.On("Health", mock.Anything).Return(errors.New("unhealthy"))

	// Alternate succeeds
	alternateResp := v1.MessagesResponse{
		Messages: map[string]common.MessageWithMetadata{
			"msg1": {},
		},
	}
	alternateClient.On("Messages", ctx, queryData).Return(200, alternateResp, nil)

	metrics.On("IncrementHeartbeatSuccess", ctx).Return()
	metrics.On("SetLastHeartbeatTimestamp", ctx, mock.AnythingOfType("int64")).Return()

	// Create adapter
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring,
		lggr:       lggr,
	}

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)

	primaryClient.AssertExpectations(t)
	alternateClient.AssertExpectations(t)
	monitoring.AssertExpectations(t)
	metrics.AssertExpectations(t)
}

func TestCallAllClients_Concurrent(t *testing.T) {
	ctx := context.Background()

	// Create multiple mock clients
	client1 := new(MockIndexerClient)
	client2 := new(MockIndexerClient)
	client3 := new(MockIndexerClient)

	input := v1.MessagesInput{}

	// Setup responses
	client1.On("Messages", ctx, input).Return(200, v1.MessagesResponse{}, nil)
	client2.On("Messages", ctx, input).Return(200, v1.MessagesResponse{}, nil)
	client3.On("Messages", ctx, input).Return(200, v1.MessagesResponse{}, nil)

	clients := []client.IndexerClientInterface{client1, client2, client3}

	// Call function
	results := callAllClients(
		ctx,
		clients,
		func(c client.IndexerClientInterface, ctx context.Context, in v1.MessagesInput) (int, v1.MessagesResponse, error) {
			return c.Messages(ctx, in)
		},
		input,
	)

	// Assert all clients were called
	assert.Len(t, results, 3)

	// Verify all clients have their results
	indices := make(map[int]bool)
	for _, r := range results {
		indices[r.idx] = true
	}
	assert.True(t, indices[0])
	assert.True(t, indices[1])
	assert.True(t, indices[2])

	client1.AssertExpectations(t)
	client2.AssertExpectations(t)
	client3.AssertExpectations(t)
}
