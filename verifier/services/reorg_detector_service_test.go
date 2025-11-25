package services

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Helper functions.
func createTestBlocks(start, end uint64) []protocol.BlockHeader {
	blocks := make([]protocol.BlockHeader, 0, end-start+1)
	for i := start; i <= end; i++ {
		blocks = append(blocks, protocol.BlockHeader{
			Number:     i,
			Hash:       protocol.Bytes32{byte(i)},
			ParentHash: protocol.Bytes32{byte(i - 1)},
			Timestamp:  time.Now(),
		})
	}
	return blocks
}

// mockGetBlocksHeaders sets up the mock to return blocks using the exact *big.Int pointers passed in.
// This is necessary because map lookups with pointer keys require exact pointer match, not just equal values.
func mockGetBlocksHeaders(mockSR *protocol_mocks.MockSourceReader, blocks []protocol.BlockHeader) {
	mockSR.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			result := make(map[*big.Int]protocol.BlockHeader)
			for _, bn := range blockNumbers {
				blockNum := bn.Uint64()
				for _, b := range blocks {
					if b.Number == blockNum {
						result[bn] = b
						break
					}
				}
			}
			return result, nil
		})
}

func TestNewReorgDetectorService(t *testing.T) {
	lggr := logger.Test(t)
	mockSR := protocol_mocks.NewMockSourceReader(t)

	t.Run("creates service with valid config", func(t *testing.T) {
		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  5 * time.Second,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)
		require.NotNil(t, service)
		assert.Equal(t, protocol.ChainSelector(1337), service.config.ChainSelector)
		assert.Equal(t, 5*time.Second, service.pollInterval)
	})

	t.Run("returns error if source reader is nil", func(t *testing.T) {
		config := ReorgDetectorConfig{ChainSelector: 1337}
		_, err := NewReorgDetectorService(nil, config, lggr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source reader is required")
	})

	t.Run("returns error if chain selector is zero", func(t *testing.T) {
		config := ReorgDetectorConfig{ChainSelector: 0}
		_, err := NewReorgDetectorService(mockSR, config, lggr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chain selector is required")
	})

	t.Run("returns error if logger is nil", func(t *testing.T) {
		config := ReorgDetectorConfig{ChainSelector: 1337}
		_, err := NewReorgDetectorService(mockSR, config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

func TestBuildEntireTail(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()

	t.Run("builds tail from finalized to latest", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  1 * time.Second,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Setup mocks
		latest := &protocol.BlockHeader{Number: 105, Hash: protocol.Bytes32{0x69}}
		finalized := &protocol.BlockHeader{Number: 100, Hash: protocol.Bytes32{0x64}}
		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		blocks := createTestBlocks(100, 105)
		mockGetBlocksHeaders(mockSR, blocks)

		err = service.buildEntireTail(ctx)
		require.NoError(t, err)

		assert.Equal(t, uint64(100), service.latestFinalizedBlock)
		assert.Equal(t, uint64(105), service.latestBlock)
		assert.Equal(t, 6, len(service.tailBlocks))
	})

	t.Run("returns error if HeadTracker fails", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(nil, nil, errors.New("rpc error"))

		err = service.buildEntireTail(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get latest and finalized blocks")
	})

	t.Run("returns error if GetBlocksHeaders fails", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)
		mockSR.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(nil, errors.New("fetch error"))

		err = service.buildEntireTail(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch block headers")
	})
}

func TestBackfillBlocks(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()

	t.Run("successfully backfills gap", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Initialize tail state
		service.latestFinalizedBlock = 100
		service.latestBlock = 100
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			100: {Number: 100, Hash: protocol.Bytes32{0x64}},
		}

		// Backfill blocks 101-103
		blocks := createTestBlocks(101, 103)
		mockGetBlocksHeaders(mockSR, blocks)

		err = service.backfillBlocks(ctx, 101, 103, 100)
		require.NoError(t, err)

		assert.Equal(t, uint64(100), service.latestFinalizedBlock)
		assert.Equal(t, uint64(103), service.latestBlock)
		assert.Equal(t, 4, len(service.tailBlocks)) // 100-103
	})

	t.Run("trims old finalized blocks during backfill", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Initialize tail with old blocks
		service.latestFinalizedBlock = 95
		service.latestBlock = 100
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			95:  {Number: 95},
			96:  {Number: 96},
			97:  {Number: 97},
			98:  {Number: 98},
			99:  {Number: 99},
			100: {Number: 100},
		}

		blocks := createTestBlocks(101, 103)
		mockGetBlocksHeaders(mockSR, blocks)

		// Finalized is now 100, should trim 95-99
		err = service.backfillBlocks(ctx, 101, 103, 100)
		require.NoError(t, err)

		assert.Equal(t, uint64(100), service.latestFinalizedBlock)
		assert.Equal(t, uint64(103), service.latestBlock)
		assert.Equal(t, 4, len(service.tailBlocks)) // 100-103
		_, exists := service.tailBlocks[95]
		assert.False(t, exists)
	})

	t.Run("returns error for invalid range", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		err = service.backfillBlocks(ctx, 105, 100, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid range")
	})
}

func TestTrimOlderBlocks(t *testing.T) {
	lggr := logger.Test(t)

	t.Run("trims blocks older than finalized", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		service.latestFinalizedBlock = 95
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			95:  {Number: 95},
			96:  {Number: 96},
			97:  {Number: 97},
			98:  {Number: 98},
			99:  {Number: 99},
			100: {Number: 100},
		}

		service.trimOlderBlocks(100)

		assert.Equal(t, uint64(100), service.latestFinalizedBlock)
		assert.Equal(t, 1, len(service.tailBlocks))
		_, exists := service.tailBlocks[100]
		assert.True(t, exists)
	})

	t.Run("does nothing if finalized is not newer", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		service.latestFinalizedBlock = 100
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			100: {Number: 100},
			101: {Number: 101},
		}

		service.trimOlderBlocks(100)

		assert.Equal(t, uint64(100), service.latestFinalizedBlock)
		assert.Equal(t, 2, len(service.tailBlocks))
	})
}

func TestAddBlockToTail(t *testing.T) {
	lggr := logger.Test(t)

	t.Run("adds block and updates tail max", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		service.latestFinalizedBlock = 100
		service.latestBlock = 100
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			100: {Number: 100},
		}

		newBlock := protocol.BlockHeader{
			Number: 101,
			Hash:   protocol.Bytes32{0x65},
		}

		service.addBlockToTail(newBlock, 100)

		assert.Equal(t, uint64(101), service.latestBlock)
		assert.Equal(t, 2, len(service.tailBlocks))
		_, exists := service.tailBlocks[101]
		assert.True(t, exists)
	})

	t.Run("trims old blocks when adding new block", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		service.latestFinalizedBlock = 95
		service.latestBlock = 100
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			95:  {Number: 95},
			100: {Number: 100},
		}

		newBlock := protocol.BlockHeader{Number: 101}
		service.addBlockToTail(newBlock, 100) // Finalized is now 100

		assert.Equal(t, uint64(100), service.latestFinalizedBlock)
		_, exists := service.tailBlocks[95]
		assert.False(t, exists)
	})
}

func TestSendNotifications(t *testing.T) {
	lggr := logger.Test(t)

	t.Run("sendReorgNotification sends correct status", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Initialize state
		service.latestFinalizedBlock = 100
		service.latestBlock = 105
		service.tailBlocks = make(map[uint64]protocol.BlockHeader)
		for i := uint64(100); i <= 105; i++ {
			service.tailBlocks[i] = protocol.BlockHeader{Number: i}
		}

		// Send notification in background
		go service.sendReorgNotification(102)

		// Receive notification
		status := <-service.statusCh
		assert.Equal(t, protocol.ReorgTypeNormal, status.Type)
		assert.Equal(t, uint64(102), status.ResetToBlock)
	})

	t.Run("sendFinalityViolation sends correct status", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		violatedBlock := protocol.BlockHeader{
			Number: 100,
			Hash:   protocol.Bytes32{0x64},
		}

		// Send notification in background
		go service.sendFinalityViolation(violatedBlock, 100)

		// Receive notification
		status := <-service.statusCh
		assert.Equal(t, protocol.ReorgTypeFinalityViolation, status.Type)
		assert.Equal(t, uint64(0), status.ResetToBlock) // No safe reset
	})

	t.Run("drops notification if channel is full", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Fill the channel (capacity is 1)
		service.statusCh <- protocol.ChainStatus{Type: protocol.ReorgTypeNormal}

		// This should not block
		service.sendReorgNotification(100)

		// Channel should still have the first message
		status := <-service.statusCh
		assert.Equal(t, protocol.ReorgTypeNormal, status.Type)

		// Channel should be empty now
		select {
		case <-service.statusCh:
			t.Fatal("Channel should be empty")
		default:
			// Expected
		}
	})
}

func TestStartAndClose(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()

	t.Run("start builds initial tail and returns channel", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  100 * time.Millisecond,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Setup mocks for initial tail
		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		blocks := createTestBlocks(100, 105)
		mockGetBlocksHeaders(mockSR, blocks)

		statusCh, err := service.Start(ctx)
		require.NoError(t, err)
		require.NotNil(t, statusCh)

		assert.Equal(t, uint64(100), service.latestFinalizedBlock)
		assert.Equal(t, uint64(105), service.latestBlock)

		// Cleanup
		service.Close()
	})

	t.Run("start fails if already started", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		blocks := createTestBlocks(100, 105)
		mockGetBlocksHeaders(mockSR, blocks)

		_, err = service.Start(ctx)
		require.NoError(t, err)

		// Try to start again
		_, err = service.Start(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ReorgDetectorService has already been started once; state=Started")

		service.Close()
	})

	t.Run("close stops polling and closes channel", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  50 * time.Millisecond,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		blocks := createTestBlocks(100, 105)
		mockGetBlocksHeaders(mockSR, blocks)

		statusCh, err := service.Start(ctx)
		require.NoError(t, err)

		// Give it a moment to start
		time.Sleep(10 * time.Millisecond)

		err = service.Close()
		require.NoError(t, err)

		// Channel should be closed
		_, ok := <-statusCh
		assert.False(t, ok, "Channel should be closed")
	})

	t.Run("close is idempotent", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		blocks := createTestBlocks(100, 105)
		mockGetBlocksHeaders(mockSR, blocks)

		_, err = service.Start(ctx)
		require.NoError(t, err)

		err = service.Close()
		require.NoError(t, err)

		err = service.Close()
		require.Error(t, err, "ReorgDetectorService has already been closed")
	})
}

func TestCheckBlockMaybeHandleReorg_ChainGoesBackwards(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()

	t.Run("detects reorg when chain goes backwards", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)
		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  1 * time.Second,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Initialize service state: chain is at block 110
		// Create a consistent chain where blocks actually connect
		service.latestFinalizedBlock = 100
		service.latestBlock = 110
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			100: {Number: 100, Hash: protocol.Bytes32{0x64}, ParentHash: protocol.Bytes32{0x63}},
			101: {Number: 101, Hash: protocol.Bytes32{0x65}, ParentHash: protocol.Bytes32{0x64}},
			102: {Number: 102, Hash: protocol.Bytes32{0x66}, ParentHash: protocol.Bytes32{0x65}},
			103: {Number: 103, Hash: protocol.Bytes32{0x67}, ParentHash: protocol.Bytes32{0x66}},
			110: {Number: 110, Hash: protocol.Bytes32{0x6E}, ParentHash: protocol.Bytes32{0x6D}},
		}

		// Simulate chain going backwards to block 105 on a different fork
		// This new block 105 has a different history than our stored blocks
		newLatest := &protocol.BlockHeader{
			Number:     105,
			Hash:       protocol.Bytes32{0xFF},
			ParentHash: protocol.Bytes32{0xFE},
		}
		finalized := &protocol.BlockHeader{Number: 100}

		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(newLatest, finalized, nil)

		// Mock walking back through the new chain to find LCA
		// Block 105's parent is 104 (new chain)
		mockSR.EXPECT().GetBlockHeaderByHash(mock.Anything, protocol.Bytes32{0xFE}).Return(
			&protocol.BlockHeader{Number: 104, Hash: protocol.Bytes32{0xFE}, ParentHash: protocol.Bytes32{0xFD}},
			nil,
		)
		// Block 104's parent is 103 (new chain)
		mockSR.EXPECT().GetBlockHeaderByHash(mock.Anything, protocol.Bytes32{0xFD}).Return(
			&protocol.BlockHeader{Number: 103, Hash: protocol.Bytes32{0xFC}, ParentHash: protocol.Bytes32{0x66}},
			nil,
		)
		// Block 103's parent is 102 (converges with old chain at block 102)
		mockSR.EXPECT().GetBlockHeaderByHash(mock.Anything, protocol.Bytes32{0x66}).Return(
			&protocol.BlockHeader{Number: 102, Hash: protocol.Bytes32{0x66}, ParentHash: protocol.Bytes32{0x65}},
			nil,
		)

		// Mock rebuilding tail from block 103 (first block after LCA which is 102)
		newChainBlocks := []protocol.BlockHeader{
			{Number: 103, Hash: protocol.Bytes32{0xFC}, ParentHash: protocol.Bytes32{0x66}},
			{Number: 104, Hash: protocol.Bytes32{0xFE}, ParentHash: protocol.Bytes32{0xFD}},
			{Number: 105, Hash: protocol.Bytes32{0xFF}, ParentHash: protocol.Bytes32{0xFE}},
		}
		mockGetBlocksHeaders(mockSR, newChainBlocks)

		// Execute
		service.checkBlockMaybeHandleReorg(ctx)

		// Verify reorg was handled - latestBlock should be updated
		assert.Equal(t, uint64(105), service.latestBlock)
		// Verify new blocks are in tail
		storedBlock, exists := service.tailBlocks[105]
		assert.True(t, exists)
		assert.Equal(t, protocol.Bytes32{0xFF}, storedBlock.Hash)
	})
}

func TestCheckBlockMaybeHandleReorg_SameBlockDifferentHash(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()

	t.Run("detects reorg when same block number has different hash via parent check", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  1 * time.Second,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Initialize service state: chain is at block 105 with a consistent chain
		service.latestFinalizedBlock = 100
		service.latestBlock = 105
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			100: {Number: 100, Hash: protocol.Bytes32{0x64}, ParentHash: protocol.Bytes32{0x63}},
			101: {Number: 101, Hash: protocol.Bytes32{0x65}, ParentHash: protocol.Bytes32{0x64}},
			102: {Number: 102, Hash: protocol.Bytes32{0x66}, ParentHash: protocol.Bytes32{0x65}},
			103: {Number: 103, Hash: protocol.Bytes32{0x67}, ParentHash: protocol.Bytes32{0x66}},
			104: {Number: 104, Hash: protocol.Bytes32{0x68}, ParentHash: protocol.Bytes32{0x67}},
			105: {Number: 105, Hash: protocol.Bytes32{0x69}, ParentHash: protocol.Bytes32{0x68}},
		}

		// Simulate same block number but different hash (competing fork at same height)
		// With refactored code, this falls through to parent hash check
		newLatest := &protocol.BlockHeader{
			Number:     105,
			Hash:       protocol.Bytes32{0xFF}, // Different hash!
			ParentHash: protocol.Bytes32{0xFE}, // Different parent - this will trigger reorg via parent check
		}
		finalized := &protocol.BlockHeader{Number: 100}

		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(newLatest, finalized, nil)

		// The parent hash (0xFE) won't match stored block 104's hash (0x68), triggering reorg
		// Mock walking back through new chain to find LCA
		mockSR.EXPECT().GetBlockHeaderByHash(mock.Anything, protocol.Bytes32{0xFE}).Return(
			&protocol.BlockHeader{Number: 104, Hash: protocol.Bytes32{0xFE}, ParentHash: protocol.Bytes32{0xFD}},
			nil,
		)
		mockSR.EXPECT().GetBlockHeaderByHash(mock.Anything, protocol.Bytes32{0xFD}).Return(
			&protocol.BlockHeader{Number: 103, Hash: protocol.Bytes32{0xFD}, ParentHash: protocol.Bytes32{0x66}},
			nil,
		)
		// Converges at block 102 (hash 0x66)
		mockSR.EXPECT().GetBlockHeaderByHash(mock.Anything, protocol.Bytes32{0x66}).Return(
			&protocol.BlockHeader{Number: 102, Hash: protocol.Bytes32{0x66}, ParentHash: protocol.Bytes32{0x65}},
			nil,
		)

		// Mock rebuilding tail from block 103 onwards (after LCA at 102)
		newChainBlocks := []protocol.BlockHeader{
			{Number: 103, Hash: protocol.Bytes32{0xFD}, ParentHash: protocol.Bytes32{0x66}},
			{Number: 104, Hash: protocol.Bytes32{0xFE}, ParentHash: protocol.Bytes32{0xFD}},
			{Number: 105, Hash: protocol.Bytes32{0xFF}, ParentHash: protocol.Bytes32{0xFE}},
		}
		mockGetBlocksHeaders(mockSR, newChainBlocks)

		// Execute
		service.checkBlockMaybeHandleReorg(ctx)

		// Verify hash was updated
		storedBlock, exists := service.tailBlocks[105]
		assert.True(t, exists)
		assert.Equal(t, protocol.Bytes32{0xFF}, storedBlock.Hash)
	})

	t.Run("no reorg when same block and same hash", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  1 * time.Second,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)

		// Initialize service state
		service.latestFinalizedBlock = 100
		service.latestBlock = 105
		service.tailBlocks = map[uint64]protocol.BlockHeader{
			105: {Number: 105, Hash: protocol.Bytes32{0x69}, ParentHash: protocol.Bytes32{0x68}},
		}

		// Same block, same hash
		latest := &protocol.BlockHeader{
			Number:     105,
			Hash:       protocol.Bytes32{0x69}, // Same hash
			ParentHash: protocol.Bytes32{0x68},
		}
		finalized := &protocol.BlockHeader{Number: 100}

		mockSR.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		// Execute - should do nothing
		service.checkBlockMaybeHandleReorg(ctx)

		// State should be unchanged
		assert.Equal(t, uint64(105), service.latestBlock)
		assert.Equal(t, 1, len(service.tailBlocks))
	})
}
