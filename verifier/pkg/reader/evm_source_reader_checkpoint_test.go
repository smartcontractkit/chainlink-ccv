package reader

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifiertypes "github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func createTestEVMSourceReader(t *testing.T, checkpointManager verifiertypes.CheckpointManager) *EVMSourceReader {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	})
	require.NoError(t, err)

	return NewEVMSourceReader(
		nil, // chain client not needed for checkpoint tests
		"0x1234567890123456789012345678901234567890", // contract address
		protocol.ChainSelector(1337),                 // chain selector
		checkpointManager,
		lggr,
	)
}

func TestEVMSourceReader_ReadCheckpointWithRetries_HappyPath(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	ctx := context.Background()
	expectedBlock := big.NewInt(12345)

	// Mock successful checkpoint read on first attempt
	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(expectedBlock, nil).
		Once()

	result, err := reader.readCheckpointWithRetries(ctx, CheckpointRetryAttempts)

	require.NoError(t, err)
	require.Equal(t, expectedBlock, result)
}

func TestEVMSourceReader_ReadCheckpointWithRetries_NoCheckpointManager(t *testing.T) {
	reader := createTestEVMSourceReader(t, nil) // No checkpoint manager

	ctx := context.Background()

	result, err := reader.readCheckpointWithRetries(ctx, CheckpointRetryAttempts)

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestEVMSourceReader_ReadCheckpointWithRetries_NoCheckpointFound(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	ctx := context.Background()

	// Mock checkpoint not found (returns nil)
	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(nil, nil).
		Once()

	result, err := reader.readCheckpointWithRetries(ctx, CheckpointRetryAttempts)

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestEVMSourceReader_ReadCheckpointWithRetries_RetryLogic(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	ctx := context.Background()
	expectedBlock := big.NewInt(54321)

	// Mock failure on first two attempts, success on third
	testErr := errors.New("checkpoint read failed")
	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr). // First failure
		Once()

	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr). // Second failure
		Once()

	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(expectedBlock, nil). // Success on third attempt
		Once()

	start := time.Now()
	result, err := reader.readCheckpointWithRetries(ctx, 3)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Equal(t, expectedBlock, result)
	// Should have some backoff delay (1s + 2s = 3s minimum)
	require.Greater(t, elapsed, 3*time.Second)
}

func TestEVMSourceReader_ReadCheckpointWithRetries_AllRetriesFail(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	ctx := context.Background()

	// Mock failure on all attempts
	testErr := errors.New("checkpoint read failed")
	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr).
		Times(3)

	result, err := reader.readCheckpointWithRetries(ctx, 3)

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to read checkpoint after 3 attempts")
}

func TestEVMSourceReader_ReadCheckpointWithRetries_ContextCancellation(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	ctx, cancel := context.WithCancel(context.Background())

	// Mock failure on first attempt
	testErr := errors.New("checkpoint read failed")
	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr).
		Once()

	// Cancel context after first failure to test cancellation during backoff
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	result, err := reader.readCheckpointWithRetries(ctx, 3)

	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, context.Canceled, err)
}

func TestEVMSourceReader_InitializeStartBlock_WithCheckpoint(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	ctx := context.Background()
	checkpointBlock := big.NewInt(1000)

	// Mock successful checkpoint read
	mockCheckpointManager.EXPECT().
		ReadCheckpoint(ctx, protocol.ChainSelector(1337)).
		Return(checkpointBlock, nil).
		Once()

	result, err := reader.initializeStartBlock(ctx)

	require.NoError(t, err)
	// Should return checkpoint + 1
	expected := big.NewInt(1001)
	require.Equal(t, expected, result)
}

func TestEVMSourceReader_UpdateCheckpoint_TooFrequent(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	ctx := context.Background()
	reader.lastCheckpointTime = time.Now() // Recent checkpoint

	// Should not call checkpoint manager
	reader.updateCheckpoint(ctx)

	// Verify no calls were made
	mockCheckpointManager.AssertNotCalled(t, "WriteCheckpoint")
}

// TestEVMSourceReader_ConstructorWithCheckpointManager verifies the constructor properly sets up checkpoint manager
func TestEVMSourceReader_ConstructorWithCheckpointManager(t *testing.T) {
	mockCheckpointManager := verifier_mocks.NewMockCheckpointManager(t)
	reader := createTestEVMSourceReader(t, mockCheckpointManager)

	require.NotNil(t, reader)
	require.Equal(t, mockCheckpointManager, reader.checkpointManager)
	require.Equal(t, protocol.ChainSelector(1337), reader.chainSelector)
}
