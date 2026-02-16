package executor

import (
	"context"
	"errors"
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

func TestGetVerifierResults_PrimarySuccess(t *testing.T) {
	tests := []struct {
		name            string
		primaryStatus   int
		primaryErr      error
		alternateStatus int
		alternateErr    error
		expectedResults int
		expectError     bool
	}{
		{
			name:            "Primary returns 200, use primary",
			primaryStatus:   200,
			primaryErr:      nil,
			alternateStatus: 200,
			alternateErr:    nil,
			expectedResults: 2,
			expectError:     false,
		},
		{
			name:            "Primary returns 404, use primary (even though error)",
			primaryStatus:   404,
			primaryErr:      errors.New("not found"),
			alternateStatus: 200,
			alternateErr:    nil,
			expectedResults: 0,
			expectError:     true,
		},
		{
			name:            "Primary returns 500, use primary",
			primaryStatus:   500,
			primaryErr:      errors.New("server error"),
			alternateStatus: 200,
			alternateErr:    nil,
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

			// Setup alternate response
			alternateResp := v1.VerifierResultsByMessageIDResponse{
				Results: []common.VerifierResultWithMetadata{
					{VerifierResult: protocol.VerifierResult{}},
				},
			}
			alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(tt.alternateStatus, alternateResp, tt.alternateErr)

			// Create adapter with noop monitoring (not testing monitoring behavior)
			lggr, _ := logger.New()
			adapter := &IndexerReaderAdapter{
				clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
				monitoring: monitoring.NewNoopExecutorMonitoring(),
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

	// Alternate should be called but not used
	alternateClient.On("VerifierResultsByMessageID", ctx, mock.Anything).Return(200, v1.VerifierResultsByMessageIDResponse{
		Results: []common.VerifierResultWithMetadata{
			{VerifierResult: protocol.VerifierResult{}},
		},
	}, nil)

	// Create adapter with noop monitoring
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring.NewNoopExecutorMonitoring(),
		lggr:       lggr,
	}

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

	// Create adapter with noop monitoring
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring.NewNoopExecutorMonitoring(),
		lggr:       lggr,
	}

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

	// Create adapter with noop monitoring
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring.NewNoopExecutorMonitoring(),
		lggr:       lggr,
	}

	// Execute
	_, err := adapter.GetVerifierResults(ctx, messageID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
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

	// Alternate should be called but not used
	alternateClient.On("Messages", ctx, queryData).Return(200, v1.MessagesResponse{Messages: map[string]common.MessageWithMetadata{}}, nil)

	// Create adapter with noop monitoring
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring.NewNoopExecutorMonitoring(),
		lggr:       lggr,
	}

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

	// Create adapter with noop monitoring
	lggr, _ := logger.New()
	adapter := &IndexerReaderAdapter{
		clients:    []client.IndexerClientInterface{primaryClient, alternateClient},
		monitoring: monitoring.NewNoopExecutorMonitoring(),
		lggr:       lggr,
	}

	// Execute
	results, err := adapter.ReadMessages(ctx, queryData)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestCallAllClients_Concurrent(t *testing.T) {
	ctx := context.Background()

	// Create multiple mock clients
	client1 := mocks.NewMockIndexerClientInterface(t)
	client2 := mocks.NewMockIndexerClientInterface(t)
	client3 := mocks.NewMockIndexerClientInterface(t)

	input := v1.MessagesInput{}

	// Setup responses with different status codes to verify correct indexing
	client1.On("Messages", ctx, input).Return(200, v1.MessagesResponse{}, nil)
	client2.On("Messages", ctx, input).Return(201, v1.MessagesResponse{}, nil)
	client3.On("Messages", ctx, input).Return(202, v1.MessagesResponse{}, nil)

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

	// Assert all clients were called and results are in correct order
	require.Len(t, results, 3)
	require.Equal(t, 200, results[0].status)
}
