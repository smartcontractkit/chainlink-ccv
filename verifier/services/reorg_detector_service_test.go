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
	mockHT := protocol_mocks.NewMockHeadTracker(t)

	t.Run("creates service with valid config", func(t *testing.T) {
		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  5 * time.Second,
		}

		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)
		require.NotNil(t, service)
		assert.Equal(t, protocol.ChainSelector(1337), service.config.ChainSelector)
		assert.Equal(t, 5*time.Second, service.pollInterval)
	})

	t.Run("uses default poll interval if not set", func(t *testing.T) {
		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  0,
		}

		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)
		assert.Equal(t, 2000*time.Millisecond, service.pollInterval)
	})

	t.Run("returns error if source reader is nil", func(t *testing.T) {
		config := ReorgDetectorConfig{ChainSelector: 1337}
		_, err := NewReorgDetectorService(nil, mockHT, config, lggr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source reader is required")
	})

	t.Run("returns error if head tracker is nil", func(t *testing.T) {
		config := ReorgDetectorConfig{ChainSelector: 1337}
		_, err := NewReorgDetectorService(mockSR, nil, config, lggr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "head tracker is required")
	})

	t.Run("returns error if chain selector is zero", func(t *testing.T) {
		config := ReorgDetectorConfig{ChainSelector: 0}
		_, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chain selector is required")
	})

	t.Run("returns error if logger is nil", func(t *testing.T) {
		config := ReorgDetectorConfig{ChainSelector: 1337}
		_, err := NewReorgDetectorService(mockSR, mockHT, config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

func TestBuildEntireTail(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()

	t.Run("builds tail from finalized to latest", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  1 * time.Second,
		}

		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)

		// Setup mocks
		latest := &protocol.BlockHeader{Number: 105, Hash: protocol.Bytes32{0x69}}
		finalized := &protocol.BlockHeader{Number: 100, Hash: protocol.Bytes32{0x64}}
		mockHT.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)

		mockHT.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(nil, nil, errors.New("rpc error"))

		err = service.buildEntireTail(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get latest and finalized blocks")
	})

	t.Run("returns error if GetBlocksHeaders fails", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockHT.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  100 * time.Millisecond,
		}

		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)

		// Setup mocks for initial tail
		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockHT.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockHT.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		blocks := createTestBlocks(100, 105)
		mockGetBlocksHeaders(mockSR, blocks)

		_, err = service.Start(ctx)
		require.NoError(t, err)

		// Try to start again
		_, err = service.Start(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already started")

		service.Close()
	})

	t.Run("close stops polling and closes channel", func(t *testing.T) {
		mockSR := protocol_mocks.NewMockSourceReader(t)
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  50 * time.Millisecond,
		}

		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockHT.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

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
		mockHT := protocol_mocks.NewMockHeadTracker(t)

		config := ReorgDetectorConfig{ChainSelector: 1337}
		service, err := NewReorgDetectorService(mockSR, mockHT, config, lggr)
		require.NoError(t, err)

		latest := &protocol.BlockHeader{Number: 105}
		finalized := &protocol.BlockHeader{Number: 100}
		mockHT.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil)

		blocks := createTestBlocks(100, 105)
		mockGetBlocksHeaders(mockSR, blocks)

		_, err = service.Start(ctx)
		require.NoError(t, err)

		err = service.Close()
		require.NoError(t, err)

		// Close again should not error
		err = service.Close()
		require.NoError(t, err)
	})
}
