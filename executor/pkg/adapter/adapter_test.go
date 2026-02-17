package executor

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
)

// newTestAdapter creates an IndexerReaderAdapter with mock clients for testing
func newTestAdapter(ctx context.Context, t *testing.T, clients []client.IndexerClientInterface) *IndexerReaderAdapter {
	t.Helper()
	lggr, _ := logger.New()
	healthCheckCtx, cancel := context.WithCancel(ctx)

	adapter := &IndexerReaderAdapter{
		clients:           clients,
		monitoring:        monitoring.NewNoopExecutorMonitoring(),
		lggr:              lggr,
		activeClientIdx:   0, // Start with primary
		healthCheckCtx:    healthCheckCtx,
		healthCheckCancel: cancel,
		mu:                sync.RWMutex{},
		healthCheckWg:     sync.WaitGroup{},
	}

	// Cleanup
	t.Cleanup(func() {
		_ = adapter.Close()
	})

	return adapter
}

func TestGetVerifierResults_PrimarySuccess(t *testing.T) {
	tests := []struct {
		name            string
		primaryStatus   int
		primaryErr      error
		expectedResults int
		expectError     bool
	}{
		{
			name:            "Primary returns 200, use primary (alternates not called)",
			primaryStatus:   200,
			primaryErr:      nil,
			expectedResults: 2,
			expectError:     false,
		},
		{
			name:            "Primary returns 404, use primary (alternates not called)",
			primaryStatus:   404,
			primaryErr:      errors.New("not found"),
			expectedResults: 0,
			expectError:     true,
		},
		{
			name:            "Primary returns 500, use primary (alternates not called)",
			primaryStatus:   500,
			primaryErr:      errors.New("server error"),
			expectedResults: 0,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			messageID := protocol.Bytes32{}

			// Setup mocks
			primaryClient := mocks.NewMockIndexerClientInterface(t)
			alternateClient := mocks.NewMockIndexerClientInterface(t)

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

			// Alternate should NOT be called when primary succeeds (status != 0)
			// No mock setup for alternate - if it gets called, the test will fail

			// Create adapter with test helper
			adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})

			// Execute
			results, err := adapter.GetVerifierResults(ctx, messageID)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, results, tt.expectedResults)
			}

			// Note: IndexerClient mocks auto-assert via cleanup when created with New*Mock(t)
		})
	}
}

func TestGetVerifierResults_PrimaryUnreachableHealthy(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

	// Primary returns status 0 (unreachable)
	primaryClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	// But health check passes
	primaryClient.On("Health", mock.Anything).Return(nil)

	// Alternate SHOULD be called concurrently with health check when primary status is 0
	alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
		},
	}, nil)

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})

	// Execute - should use primary despite status 0 because health check passes
	_, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should return primary's error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")

	// Note: IndexerClient mocks auto-assert via cleanup when created with New*Mock(t)
}

func TestGetVerifierResults_PrimaryUnreachableUnhealthyFailover(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

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

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})

	// Execute - should use alternate
	results, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should succeed with alternate's results
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Note: IndexerClient mocks auto-assert via cleanup when created with New*Mock(t)
}

func TestGetVerifierResults_AllClientsUnreachable_UsesPrimary(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

	// Primary returns status 0 (unreachable) and unhealthy
	primaryClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	primaryClient.On("Health", mock.Anything).Return(errors.New("unhealthy"))

	// Alternate also returns status 0
	alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection timeout"))

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})

	// Execute
	_, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should return primary's error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestGetVerifierResults_NonPrimaryActiveSuccess(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

	// Set up adapter with alternate as active (simulating previous failover)
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})
	adapter.setActiveClientIdx(1) // Use alternate

	// Only alternate should be called when it's the active client
	alternateResp := v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
			{VerifierResult: protocol.VerifierResult{}},
		},
	}
	alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, alternateResp, nil)

	// Execute
	results, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should use alternate successfully
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should still be on alternate")
}

func TestReadMessages_PrimarySuccess(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

	// Primary succeeds
	primaryResp := v1.MessagesResponse{
		Messages: map[string]common.MessageWithMetadata{
			"msg1": {},
			"msg2": {},
		},
	}
	primaryClient.On("Messages", ctx, queryData).Return(200, primaryResp, nil)

	// Alternate should NOT be called when primary succeeds (status != 0)
	// No mock setup for alternate - if it gets called, the test will fail

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestReadMessages_PrimaryUnreachableFailover(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

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

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)
	// Note: activeClientIdx is set to 1 after this failover
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should have failed over to alternate")
}

func TestReadMessages_NonPrimaryActive(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

	// Set up adapter with alternate as active
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})
	adapter.setActiveClientIdx(1)

	// Only alternate should be called
	alternateResp := v1.MessagesResponse{
		Messages: map[string]common.MessageWithMetadata{
			"msg1": {},
			"msg2": {},
		},
	}
	alternateClient.On("Messages", ctx, queryData).Return(200, alternateResp, nil)

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should still be on alternate")
}

func TestAdapter_Close(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	primaryClient := mocks.NewMockIndexerClientInterface(t)
	alternateClient := mocks.NewMockIndexerClientInterface(t)

	// Create adapter
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{primaryClient, alternateClient})

	// Close should not error
	err := adapter.Close()
	assert.NoError(t, err)

	// Calling close again should be safe
	err = adapter.Close()
	assert.NoError(t, err)
}
