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

func createTestSourceReader(t *testing.T, chainStatusManager protocol.ChainStatusManager) *SourceReaderService {
	return NewSourceReaderService(
		nil,
		protocol.ChainSelector(1337),
		chainStatusManager,
		logger.Test(t),
		50*time.Millisecond,
	)
}

func TestEVMSourceReader_ReadChainStatusWithRetries_HappyPath(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()
	expectedBlock := big.NewInt(12345)

	// Mock successful chain status read on first attempt
	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(expectedBlock, nil).
		Once()

	result, err := reader.readChainStatusWithRetries(ctx, ChainStatusRetryAttempts)

	require.NoError(t, err)
	require.Equal(t, expectedBlock, result)
}

func TestEVMSourceReader_ReadChainStatusWithRetries_NoChainStatusManager(t *testing.T) {
	reader := createTestSourceReader(t, nil) // No chain status manager

	ctx := context.Background()

	result, err := reader.readChainStatusWithRetries(ctx, ChainStatusRetryAttempts)

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestEVMSourceReader_ReadChainStatusWithRetries_NoChainStatusFound(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()

	// Mock chain status not found (returns nil)
	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(nil, nil).
		Once()

	result, err := reader.readChainStatusWithRetries(ctx, ChainStatusRetryAttempts)

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestEVMSourceReader_ReadChainStatusWithRetries_RetryLogic(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()
	expectedBlock := big.NewInt(54321)

	// Mock failure on first two attempts, success on third
	testErr := errors.New("chainStatus read failed")
	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr). // First failure
		Once()

	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr). // Second failure
		Once()

	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(expectedBlock, nil). // Success on third attempt
		Once()

	start := time.Now()
	result, err := reader.readChainStatusWithRetries(ctx, 3)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Equal(t, expectedBlock, result)
	// Should have some backoff delay (1s + 2s = 3s minimum)
	require.Greater(t, elapsed, 3*time.Second)
}

func TestEVMSourceReader_ReadChainStatusWithRetries_AllRetriesFail(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()

	// Mock failure on all attempts
	testErr := errors.New("chainStatus read failed")
	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr).
		Times(3)

	result, err := reader.readChainStatusWithRetries(ctx, 3)

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to read chainStatus after 3 attempts")
}

func TestEVMSourceReader_ReadChainStatusWithRetries_ContextCancellation(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx, cancel := context.WithCancel(context.Background())

	// Mock failure on first attempt
	testErr := errors.New("chainStatus read failed")
	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(nil, testErr).
		Once()

	// Cancel context after first failure to test cancellation during backoff
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	result, err := reader.readChainStatusWithRetries(ctx, 3)

	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, context.Canceled, err)
}

func TestEVMSourceReader_InitializeStartBlock_WithChainStatus(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()
	chainStatusBlock := big.NewInt(1000)

	// Mock successful chain status read
	mockChainStatusManager.EXPECT().
		ReadChainStatus(ctx, protocol.ChainSelector(1337)).
		Return(chainStatusBlock, nil).
		Once()

	result, err := reader.initializeStartBlock(ctx)

	require.NoError(t, err)
	// Should return chain status + 1
	expected := big.NewInt(1001)
	require.Equal(t, expected, result)
}

func TestEVMSourceReader_UpdateChainStatus_TooFrequent(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()
	reader.lastChainStatusTime = time.Now() // Recent chain status

	// Should not call chain status manager
	reader.updateChainStatus(ctx, big.NewInt(2000))

	// Verify no calls were made
	mockChainStatusManager.AssertNotCalled(t, "WriteChainStatus")
}

// TestEVMSourceReader_ConstructorWithChainStatusManager verifies the constructor properly sets up chain status manager.
func TestEVMSourceReader_ConstructorWithChainStatusManager(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	require.NotNil(t, reader)
	require.Equal(t, mockChainStatusManager, reader.chainStatusManager)
	require.Equal(t, protocol.ChainSelector(1337), reader.chainSelector)
}

// TestSourceReaderService_ResetToBlock_WithChainStatusWrite tests reset when resetBlock < lastChainStatusBlock (finality violation).
func TestSourceReaderService_ResetToBlock_WithChainStatusWrite(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000, chain statused at 1980
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastChainStatusBlock = big.NewInt(1980)

	// Reset to block 500 (finality violation scenario)
	resetBlock := uint64(500)

	// Expect chain status write since 500 < 1980
	mockChainStatusManager.EXPECT().
		WriteChainStatus(ctx, protocol.ChainSelector(1337), big.NewInt(int64(resetBlock))).
		Return(nil).
		Once()

	err := reader.ResetToBlock(ctx, resetBlock)

	require.NoError(t, err)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastProcessedBlock)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastChainStatusBlock)
	mockChainStatusManager.AssertExpectations(t)
}

// TestSourceReaderService_ResetToBlock_WithoutChainStatusWrite tests reset when resetBlock >= lastChainStatusBlock (regular reorg).
func TestSourceReaderService_ResetToBlock_WithoutChainStatusWrite(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000, chain statused at 1980
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastChainStatusBlock = big.NewInt(1980)

	// Reset to block 1990 (regular reorg scenario - common ancestor above chain status)
	resetBlock := uint64(1990)

	// Should NOT write chain status since 1990 > 1980
	// Periodic chain statusing will handle it naturally

	err := reader.ResetToBlock(ctx, resetBlock)

	require.NoError(t, err)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastProcessedBlock)
	// lastChainStatusBlock should remain unchanged
	require.Equal(t, big.NewInt(1980), reader.lastChainStatusBlock)
	mockChainStatusManager.AssertNotCalled(t, "WriteChainStatus")
}

// TestSourceReaderService_ResetToBlock_ChainStatusWriteError tests error handling during chain status write.
func TestSourceReaderService_ResetToBlock_ChainStatusWriteError(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000, chain statused at 1980
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastChainStatusBlock = big.NewInt(1980)

	// Reset to block 500 (finality violation scenario)
	resetBlock := uint64(500)

	// ChainStatus write fails
	chainStatusErr := errors.New("chainStatus write failed")
	mockChainStatusManager.EXPECT().
		WriteChainStatus(ctx, protocol.ChainSelector(1337), big.NewInt(int64(resetBlock))).
		Return(chainStatusErr).
		Once()

	err := reader.ResetToBlock(ctx, resetBlock)

	// Should return error and NOT update lastProcessedBlock
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to persist reset chainStatus")
	require.Equal(t, big.NewInt(2000), reader.lastProcessedBlock) // Unchanged
	mockChainStatusManager.AssertExpectations(t)
}

// TestSourceReaderService_ResetToBlock_NoChainStatusManager tests reset when no chain status manager is configured.
func TestSourceReaderService_ResetToBlock_NoChainStatusManager(t *testing.T) {
	reader := createTestSourceReader(t, nil) // No chain status manager

	ctx := context.Background()

	// Setup: source reader has processed up to block 2000
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastChainStatusBlock = big.NewInt(1980)

	// Reset to block 500
	resetBlock := uint64(500)

	err := reader.ResetToBlock(ctx, resetBlock)

	// Should succeed without chain status write
	require.NoError(t, err)
	require.Equal(t, big.NewInt(int64(resetBlock)), reader.lastProcessedBlock)
}

// TestSourceReaderService_ResetToBlock_IncrementsVersion tests that resetVersion is incremented.
func TestSourceReaderService_ResetToBlock_IncrementsVersion(t *testing.T) {
	mockChainStatusManager := mocks.NewMockChainStatusManager(t)
	reader := createTestSourceReader(t, mockChainStatusManager)

	ctx := context.Background()

	// Setup
	reader.lastProcessedBlock = big.NewInt(2000)
	reader.lastChainStatusBlock = big.NewInt(1980)

	initialVersion := reader.resetVersion.Load()

	// Reset to block 1990 (no chain status write needed)
	err := reader.ResetToBlock(ctx, 1990)

	require.NoError(t, err)
	// Verify version was incremented
	require.Equal(t, initialVersion+1, reader.resetVersion.Load())
}
