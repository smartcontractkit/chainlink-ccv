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

// newTestAdapter creates an IndexerReaderAdapter with mock clients for testing.
func newTestAdapter(ctx context.Context, t *testing.T, clients []client.IndexerClientInterface) *IndexerReaderAdapter {
	t.Helper()
	lggr, _ := logger.New()

	adapter := &IndexerReaderAdapter{
		clients:         clients,
		monitoring:      monitoring.NewNoopExecutorMonitoring(),
		lggr:            lggr,
		activeClientIdx: 0, // Start with first client
		mu:              sync.RWMutex{},
	}

	return adapter
}

func TestGetVerifierResults_ActiveClientSuccess(t *testing.T) {
	tests := []struct {
		name            string
		activeStatus    int
		activeErr       error
		expectedResults int
		expectError     bool
	}{
		{
			name:            "Active returns 200 (alternates not called)",
			activeStatus:    200,
			activeErr:       nil,
			expectedResults: 2,
			expectError:     false,
		},
		{
			name:            "Active returns 404 (alternates not called)",
			activeStatus:    404,
			activeErr:       errors.New("not found"),
			expectedResults: 0,
			expectError:     true,
		},
		{
			name:            "Active returns 500 (alternates not called)",
			activeStatus:    500,
			activeErr:       errors.New("server error"),
			expectedResults: 0,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			messageID := protocol.Bytes32{}

			// Setup mocks
			activeClient := mocks.NewMockIndexerClientInterface(t)
			alternateClient := mocks.NewMockIndexerClientInterface(t)

			// Setup active client response
			activeResp := v1.VerifierResultsByMessageIDResponse{
				Results: []common.VerifierResultWithMetadata{
					{VerifierResult: protocol.VerifierResult{}},
					{VerifierResult: protocol.VerifierResult{}},
				},
			}
			if tt.activeErr != nil {
				activeResp = v1.VerifierResultsByMessageIDResponse{}
			}

			activeClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(tt.activeStatus, activeResp, tt.activeErr)

			// Alternate should NOT be called when active succeeds (status != 0)
			// No mock setup for alternate - if it gets called, the test will fail

			// Create adapter with test helper
			adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{activeClient, alternateClient})

			// Execute
			results, err := adapter.GetVerifierResults(ctx, messageID)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, results, tt.expectedResults)
			}
		})
	}
}

func TestGetVerifierResults_ActiveUnreachableButHealthy(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Active client returns status 0 (unreachable)
	client0.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	// But health check passes
	client0.On("Health", mock.Anything).Return(nil)

	// Alternate SHOULD be called concurrently with health check when active status is 0
	client1.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
		},
	}, nil)

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})

	// Execute - should use active despite status 0 because health check passes
	_, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should return active client's error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Equal(t, 0, adapter.getActiveClientIdx(), "Should stay on client 0")
}

func TestGetVerifierResults_ActiveUnhealthyFailover(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Active client returns status 0 (unreachable) and unhealthy
	client0.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	client0.On("Health", mock.Anything).Return(errors.New("unhealthy"))

	// Alternate succeeds
	alternateResp := v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
			{VerifierResult: protocol.VerifierResult{}},
		},
	}
	client1.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, alternateResp, nil)

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})

	// Execute - should failover to alternate
	results, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should succeed with alternate's results
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should have failed over to client 1")
}

func TestGetVerifierResults_AllClientsUnreachable(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Active client returns status 0 (unreachable) and unhealthy
	client0.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused"))
	client0.On("Health", mock.Anything).Return(errors.New("unhealthy"))

	// Alternate also returns status 0
	client1.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection timeout"))

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})

	// Execute
	_, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert - should return active client's error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Equal(t, 0, adapter.getActiveClientIdx(), "Should stay on client 0")
}

func TestGetVerifierResults_ActiveOnClient1Success(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Set up adapter with client 1 as active (simulating previous failover)
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})
	adapter.setActiveClientIdx(1)

	// Only active client should be called
	activeResp := v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
			{VerifierResult: protocol.VerifierResult{}},
		},
	}
	client1.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, activeResp, nil)

	// Execute
	results, err := adapter.GetVerifierResults(ctx, messageID)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should stay on client 1")
}

func TestReadMessages_ActiveClientSuccess(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Active client succeeds
	activeResp := v1.MessagesResponse{
		Messages: map[string]common.MessageWithMetadata{
			"msg1": {},
			"msg2": {},
		},
	}
	client0.On("Messages", ctx, queryData).Return(200, activeResp, nil)

	// Alternate should NOT be called when active succeeds (status != 0)
	// No mock setup for client1 - if it gets called, the test will fail

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestReadMessages_ActiveUnhealthyFailover(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Active client returns status 0 and unhealthy
	client0.On("Messages", ctx, queryData).Return(0, v1.MessagesResponse{}, errors.New("connection refused"))
	client0.On("Health", mock.Anything).Return(errors.New("unhealthy"))

	// Alternate succeeds
	alternateResp := v1.MessagesResponse{
		Messages: map[string]common.MessageWithMetadata{
			"msg1": {},
		},
	}
	client1.On("Messages", ctx, queryData).Return(200, alternateResp, nil)

	// Create adapter with test helper
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should have failed over to client 1")
}

func TestReadMessages_ActiveOnClient1(t *testing.T) {
	ctx := context.Background()
	queryData := v1.MessagesInput{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Set up adapter with client 1 as active
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})
	adapter.setActiveClientIdx(1)

	// Only active client should be called
	activeResp := v1.MessagesResponse{
		Messages: map[string]common.MessageWithMetadata{
			"msg1": {},
			"msg2": {},
		},
	}
	client1.On("Messages", ctx, queryData).Return(200, activeResp, nil)

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should stay on client 1")
}

func TestGetVerifierResults_Failover_PersistsOnAlternate(t *testing.T) {
	ctx := context.Background()
	messageID := protocol.Bytes32{}

	// Setup mocks
	client0 := mocks.NewMockIndexerClientInterface(t)
	client1 := mocks.NewMockIndexerClientInterface(t)

	// Create adapter starting on client 0
	adapter := newTestAdapter(ctx, t, []client.IndexerClientInterface{client0, client1})

	// First request: Client 0 fails, health check fails, failover to client 1
	client0.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(0, v1.VerifierResultsByMessageIDResponse{}, errors.New("connection refused")).Once()
	client0.On("Health", mock.Anything).Return(errors.New("unhealthy")).Once()

	alternateResp := v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
		},
	}
	client1.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, alternateResp, nil)

	// Execute first request
	results, err := adapter.GetVerifierResults(ctx, messageID)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should have failed over to client 1")

	// Second request: Should use client 1 directly, client 0 should NOT be called
	results2, err := adapter.GetVerifierResults(ctx, messageID)
	require.NoError(t, err)
	assert.Len(t, results2, 1)
	assert.Equal(t, 1, adapter.getActiveClientIdx(), "Should persist on client 1")

	// Note: If client 0 was called again, the test would fail because we used .Once()
}
