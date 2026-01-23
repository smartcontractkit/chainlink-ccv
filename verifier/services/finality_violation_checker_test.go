package services

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// MockSourceReaderSetup contains a mock source Reader and its Channel.
// This follows the same pattern as verifier.MockSourceReaderSetup but is local to this package.
type MockSourceReaderSetup struct {
	Reader  *mocks.MockSourceReader
	Channel chan protocol.MessageSentEvent
}

// setupMockSourceReaderForFinality creates a mock source Reader with configurable block headers.
func setupMockSourceReaderForFinality(t *testing.T, blocks map[uint64]protocol.BlockHeader) *MockSourceReaderSetup {
	mockReader := mocks.NewMockSourceReader(t)
	channel := make(chan protocol.MessageSentEvent, 10)

	// now := time.Now().Unix()

	// mockReader.EXPECT().BlockTime(mock.Anything, mock.Anything).Return(uint64(now), nil).Maybe()
	mockReader.EXPECT().GetRMNCursedSubjects(mock.Anything).Return(nil, nil).Maybe()
	mockReader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(nil, nil, nil).Maybe()
	mockReader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	// mockReader.EXPECT().GetBlockHeaderByHash(mock.Anything, mock.Anything).Return(nil, nil).Maybe()

	// Mock GetBlocksHeaders to return headers from the provided blocks map
	mockReader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			headers := make(map[*big.Int]protocol.BlockHeader)
			for _, blockNum := range blockNumbers {
				if header, exists := blocks[blockNum.Uint64()]; exists {
					headers[blockNum] = header
				}
			}
			return headers, nil
		},
	).Maybe()

	return &MockSourceReaderSetup{
		Reader:  mockReader,
		Channel: channel,
	}
}

func makeBytes32(s string) protocol.Bytes32 {
	var b protocol.Bytes32
	copy(b[:], s)
	return b
}

func TestFinalityViolationChecker_NormalOperation(t *testing.T) {
	lggr, _ := logger.New()

	blocks := map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
		101: {Number: 101, Hash: makeBytes32("hash101"), ParentHash: makeBytes32("hash100")},
		102: {Number: 102, Hash: makeBytes32("hash102"), ParentHash: makeBytes32("hash101")},
		103: {Number: 103, Hash: makeBytes32("hash103"), ParentHash: makeBytes32("hash102")},
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// First update - initialize
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())

	// Second update - advance finality
	err = checker.UpdateFinalized(ctx, 101)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())

	// Third update - advance more
	err = checker.UpdateFinalized(ctx, 103)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())

	// No violations should be detected
	assert.False(t, checker.IsFinalityViolated())
}

func TestFinalityViolationChecker_DetectsViolation(t *testing.T) {
	lggr, _ := logger.New()

	blocks := map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
		101: {Number: 101, Hash: makeBytes32("hash101"), ParentHash: makeBytes32("hash100")},
		102: {Number: 102, Hash: makeBytes32("hash102"), ParentHash: makeBytes32("hash101")},
		103: {Number: 103, Hash: makeBytes32("hash103"), ParentHash: makeBytes32("hash102")},
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize with block 100
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())

	// Advance to 101
	err = checker.UpdateFinalized(ctx, 101)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())

	// Simulate finality violation - block 101 hash changes in the RPC
	// This would happen if the node's finalized block was reorged
	blocks[101] = protocol.BlockHeader{Number: 101, Hash: makeBytes32("DIFFERENT"), ParentHash: makeBytes32("hash100")}
	// Re-setup the mock expectation with updated blocks
	mockSetup.Reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			headers := make(map[*big.Int]protocol.BlockHeader)
			for _, blockNum := range blockNumbers {
				if header, exists := blocks[blockNum.Uint64()]; exists {
					headers[blockNum] = header
				}
			}
			return headers, nil
		},
	).Maybe()

	// Try to advance finality to 102 - will fetch blocks 101-102
	// Block 101 will be re-fetched and hash mismatch detected
	err = checker.UpdateFinalized(ctx, 102)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "finality violation")
	assert.True(t, checker.IsFinalityViolated())

	// Further updates should fail
	err = checker.UpdateFinalized(ctx, 103)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "finality violation already detected")
}

func TestFinalityViolationChecker_Reset(t *testing.T) {
	lggr, _ := logger.New()

	blocks := map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
		101: {Number: 101, Hash: makeBytes32("hash101"), ParentHash: makeBytes32("hash100")},
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// reset
	checker.reset()

	// Should be able to initialize again
	err = checker.UpdateFinalized(ctx, 101)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())
}

func TestFinalityViolationChecker_NoAdvancement(t *testing.T) {
	lggr, _ := logger.New()

	blocks := map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize with block 100
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// Update with same block - should verify hash and succeed
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())
}

func TestFinalityViolationChecker_BackwardMovementConsistentHashes_NoViolation(t *testing.T) {
	lggr, _ := logger.New()

	blocks := map[uint64]protocol.BlockHeader{
		99:  {Number: 99, Hash: makeBytes32("hash99"), ParentHash: makeBytes32("hash98")},
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize with block 100
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// Update with earlier block - RPC lagging, but hashes are consistent
	// Should NOT be a violation since all hashes verify correctly
	err = checker.UpdateFinalized(ctx, 99)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())
}

func TestFinalityViolationChecker_BackwardMovementHashChanged_Violation(t *testing.T) {
	lggr, _ := logger.New()

	blocks := map[uint64]protocol.BlockHeader{
		99:  {Number: 99, Hash: makeBytes32("hash99"), ParentHash: makeBytes32("hash98")},
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize with block 100
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// Simulate reorg: block 100's hash changed
	blocks[100] = protocol.BlockHeader{Number: 100, Hash: makeBytes32("REORGED"), ParentHash: makeBytes32("hash99")}

	// Update with earlier block - should detect hash mismatch on block 100
	err = checker.UpdateFinalized(ctx, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "finality violation")
	assert.Contains(t, err.Error(), "hash changed")
	assert.True(t, checker.IsFinalityViolated())
}

func TestFinalityViolationChecker_SameHeightHashChange(t *testing.T) {
	lggr, _ := logger.New()

	blocks := map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize with block 100
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// Change the hash at the same height
	blocks[100] = protocol.BlockHeader{Number: 100, Hash: makeBytes32("DIFFERENT"), ParentHash: makeBytes32("hash99")}
	// Re-setup the mock expectation with updated blocks
	mockSetup.Reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			headers := make(map[*big.Int]protocol.BlockHeader)
			for _, blockNum := range blockNumbers {
				if header, exists := blocks[blockNum.Uint64()]; exists {
					headers[blockNum] = header
				}
			}
			return headers, nil
		},
	).Maybe()

	// Update with same block - should detect hash change
	err = checker.UpdateFinalized(ctx, 100)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "finality violation")
	assert.Contains(t, err.Error(), "hash changed")
	assert.True(t, checker.IsFinalityViolated())
}

func TestFinalityViolationChecker_ParentHashMismatch(t *testing.T) {
	lggr, _ := logger.New()

	// Block 101's parent hash doesn't match block 100's hash - simulates mid-fetch reorg
	blocks := map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: makeBytes32("hash100"), ParentHash: makeBytes32("hash99")},
		101: {Number: 101, Hash: makeBytes32("hash101"), ParentHash: makeBytes32("WRONG_PARENT")}, // Wrong parent!
	}
	mockSetup := setupMockSourceReaderForFinality(t, blocks)

	checker, err := NewFinalityViolationCheckerService(mockSetup.Reader, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize with block 100
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())

	// Try to advance to 101 - should detect parent hash mismatch
	err = checker.UpdateFinalized(ctx, 101)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "finality violation")
	assert.Contains(t, err.Error(), "parent hash")
	assert.True(t, checker.IsFinalityViolated())
}

func TestNoOpFinalityViolationChecker(t *testing.T) {
	checker := &NoOpFinalityViolationChecker{}
	ctx := context.Background()

	// Should always return nil error
	err := checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// Should always return false for violation
	assert.False(t, checker.IsFinalityViolated())

	// Even with different blocks
	err = checker.UpdateFinalized(ctx, 200)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())
}
