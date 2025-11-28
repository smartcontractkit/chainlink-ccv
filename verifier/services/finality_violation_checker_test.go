package services

import (
	"context"
	"math/big"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSourceReaderForFinality is a simple mock for testing finality checker
type mockSourceReaderForFinality struct {
	blocks map[uint64]protocol.BlockHeader
}

func (m *mockSourceReaderForFinality) GetBlocksHeaders(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
	result := make(map[*big.Int]protocol.BlockHeader)
	for _, num := range blockNumbers {
		if header, exists := m.blocks[num.Uint64()]; exists {
			result[num] = header
		}
	}
	return result, nil
}

func (m *mockSourceReaderForFinality) LatestAndFinalizedBlock(ctx context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
	return nil, nil, nil
}

func (m *mockSourceReaderForFinality) ReadMessagesInBlockRange(ctx context.Context, from, to *big.Int) ([]protocol.Message, error) {
	return nil, nil
}

func (m *mockSourceReaderForFinality) FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error) {
	return nil, nil
}

func (m *mockSourceReaderForFinality) BlockTime(ctx context.Context, block *big.Int) (uint64, error) {
	return 0, nil
}

func (m *mockSourceReaderForFinality) GetBlockHeaderByHash(ctx context.Context, hash protocol.Bytes32) (*protocol.BlockHeader, error) {
	return nil, nil
}

func (m *mockSourceReaderForFinality) GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error) {
	return nil, nil
}

func makeBytes32(s string) protocol.Bytes32 {
	var b protocol.Bytes32
	copy(b[:], s)
	return b
}

func TestFinalityViolationChecker_NormalOperation(t *testing.T) {
	lggr, _ := logger.New()

	mock := &mockSourceReaderForFinality{
		blocks: map[uint64]protocol.BlockHeader{
			100: {Number: 100, Hash: makeBytes32("hash100")},
			101: {Number: 101, Hash: makeBytes32("hash101")},
			102: {Number: 102, Hash: makeBytes32("hash102")},
			103: {Number: 103, Hash: makeBytes32("hash103")},
		},
	}

	checker, err := NewFinalityViolationCheckerService(mock, protocol.ChainSelector(1), lggr)
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

	mock := &mockSourceReaderForFinality{
		blocks: map[uint64]protocol.BlockHeader{
			100: {Number: 100, Hash: makeBytes32("hash100")},
			101: {Number: 101, Hash: makeBytes32("hash101")},
			102: {Number: 102, Hash: makeBytes32("hash102")},
			103: {Number: 103, Hash: makeBytes32("hash103")},
		},
	}

	checker, err := NewFinalityViolationCheckerService(mock, protocol.ChainSelector(1), lggr)
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
	mock.blocks[101] = protocol.BlockHeader{Number: 101, Hash: makeBytes32("DIFFERENT")}

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

	mock := &mockSourceReaderForFinality{
		blocks: map[uint64]protocol.BlockHeader{
			100: {Number: 100, Hash: makeBytes32("hash100")},
			101: {Number: 101, Hash: makeBytes32("hash101")},
		},
	}

	checker, err := NewFinalityViolationCheckerService(mock, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// Reset
	checker.Reset()

	// Should be able to initialize again
	err = checker.UpdateFinalized(ctx, 101)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())
}

func TestFinalityViolationChecker_NoAdvancement(t *testing.T) {
	lggr, _ := logger.New()

	mock := &mockSourceReaderForFinality{
		blocks: map[uint64]protocol.BlockHeader{
			100: {Number: 100, Hash: makeBytes32("hash100")},
		},
	}

	checker, err := NewFinalityViolationCheckerService(mock, protocol.ChainSelector(1), lggr)
	require.NoError(t, err)

	ctx := context.Background()

	// Initialize with block 100
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)

	// Update with same block - should be no-op
	err = checker.UpdateFinalized(ctx, 100)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())

	// Update with earlier block - should be no-op
	err = checker.UpdateFinalized(ctx, 99)
	require.NoError(t, err)
	assert.False(t, checker.IsFinalityViolated())
}
