package verifier

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func createTestSourceReader(t *testing.T, checkpointManager protocol.CheckpointManager) *SourceReaderService {
	return NewSourceReaderService(
		nil,
		protocol.ChainSelector(1337),
		checkpointManager,
		logger.Test(t),
		50*time.Millisecond,
	)
}

func TestEVMSourceReader_ReadCheckpointWithRetries_HappyPath(t *testing.T) {
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

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
	reader := createTestSourceReader(t, nil) // No checkpoint manager

	ctx := context.Background()

	result, err := reader.readCheckpointWithRetries(ctx, CheckpointRetryAttempts)

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestEVMSourceReader_ReadCheckpointWithRetries_NoCheckpointFound(t *testing.T) {
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

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
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

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
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

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
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

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
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

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
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

	ctx := context.Background()
	reader.lastCheckpointTime = time.Now() // Recent checkpoint

	// Should not call checkpoint manager
	reader.updateCheckpoint(ctx, big.NewInt(2000))

	// Verify no calls were made
	mockCheckpointManager.AssertNotCalled(t, "WriteCheckpoint")
}

// TestEVMSourceReader_ConstructorWithCheckpointManager verifies the constructor properly sets up checkpoint manager.
func TestEVMSourceReader_ConstructorWithCheckpointManager(t *testing.T) {
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

	require.NotNil(t, reader)
	require.Equal(t, mockCheckpointManager, reader.checkpointManager)
	require.Equal(t, protocol.ChainSelector(1337), reader.chainSelector)
}

// TestSourceReaderService_ResetToBlock_WithCheckpointWrite tests reset when resetBlock < lastCheckpointedBlock (finality violation).
func TestSourceReaderService_ResetToBlock_WithCheckpointWrite(t *testing.T) {
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000, checkpointed at 1980
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastCheckpointedBlock = big.NewInt(1980)

	// Reset to block 500 (finality violation scenario)
	resetBlock := uint64(500)

	// Expect checkpoint write since 500 < 1980
	mockCheckpointManager.EXPECT().
		WriteCheckpoint(ctx, protocol.ChainSelector(1337), big.NewInt(int64(resetBlock))).
		Return(nil).
		Once()

	err := reader.ResetToBlock(ctx, resetBlock)

	require.NoError(t, err)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastProcessedBlock)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastCheckpointedBlock)
	mockCheckpointManager.AssertExpectations(t)
}

// TestSourceReaderService_ResetToBlock_WithoutCheckpointWrite tests reset when resetBlock >= lastCheckpointedBlock (regular reorg).
func TestSourceReaderService_ResetToBlock_WithoutCheckpointWrite(t *testing.T) {
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000, checkpointed at 1980
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastCheckpointedBlock = big.NewInt(1980)

	// Reset to block 1990 (regular reorg scenario - common ancestor above checkpoint)
	resetBlock := uint64(1990)

	// Should NOT write checkpoint since 1990 > 1980
	// Periodic checkpointing will handle it naturally

	err := reader.ResetToBlock(ctx, resetBlock)

	require.NoError(t, err)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastProcessedBlock)
	// lastCheckpointedBlock should remain unchanged
	require.Equal(t, big.NewInt(1980), reader.lastCheckpointedBlock)
	mockCheckpointManager.AssertNotCalled(t, "WriteCheckpoint")
}

// TestSourceReaderService_ResetToBlock_CheckpointWriteError tests error handling during checkpoint write.
func TestSourceReaderService_ResetToBlock_CheckpointWriteError(t *testing.T) {
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000, checkpointed at 1980
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastCheckpointedBlock = big.NewInt(1980)

	// Reset to block 500 (finality violation scenario)
	resetBlock := uint64(500)

	// Checkpoint write fails
	checkpointErr := errors.New("checkpoint write failed")
	mockCheckpointManager.EXPECT().
		WriteCheckpoint(ctx, protocol.ChainSelector(1337), big.NewInt(int64(resetBlock))).
		Return(checkpointErr).
		Once()

	err := reader.ResetToBlock(ctx, resetBlock)

	// Should return error and NOT update lastProcessedBlock
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to persist reset checkpoint")
	require.Equal(t, big.NewInt(2000), reader.lastProcessedBlock) // Unchanged
	mockCheckpointManager.AssertExpectations(t)
}

// TestSourceReaderService_ResetToBlock_NoCheckpointManager tests reset when no checkpoint manager is configured.
func TestSourceReaderService_ResetToBlock_NoCheckpointManager(t *testing.T) {
	reader := createTestSourceReader(t, nil) // No checkpoint manager

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastCheckpointedBlock = big.NewInt(1980)

	// Reset to block 500
	resetBlock := uint64(500)

	err := reader.ResetToBlock(ctx, resetBlock)

	// Should succeed without checkpoint write
	require.NoError(t, err)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastProcessedBlock)
}

// TestSourceReaderService_ResetToBlock_IncrementsVersion tests that resetVersion is incremented.
func TestSourceReaderService_ResetToBlock_IncrementsVersion(t *testing.T) {
	mockCheckpointManager := mocks.NewMockCheckpointManager(t)
	reader := createTestSourceReader(t, mockCheckpointManager)

	ctx := context.Background()

	// Setup
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastCheckpointedBlock = big.NewInt(1980)

	initialVersion := reader.resetVersion.Load()

	// Reset to block 1990 (no checkpoint write needed)
	err := reader.ResetToBlock(ctx, 1990)

	require.NoError(t, err)
	// Verify version was incremented
	require.Equal(t, initialVersion+1, reader.resetVersion.Load())
}
