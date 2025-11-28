package services

import (
	"context"
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
	mockSR.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Unset()
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

	t.Run("uses default poll interval if not set", func(t *testing.T) {
		config := ReorgDetectorConfig{
			ChainSelector: 1337,
			PollInterval:  0,
		}

		service, err := NewReorgDetectorService(mockSR, config, lggr)
		require.NoError(t, err)
		assert.Equal(t, DefaultPollInterval, service.pollInterval)
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

func TestTrimOlderBlocks(t *testing.T) {
	lggr := logger.Test(t)

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

func TestIsFinalityViolated_TableDriven(t *testing.T) {
	lggr := logger.Test(t)
	mockSR := protocol_mocks.NewMockSourceReader(t)

	config := ReorgDetectorConfig{ChainSelector: 1337}

	type testCase struct {
		name            string
		setup           func(svc *ReorgDetectorService)
		latest          *protocol.BlockHeader
		finalized       *protocol.BlockHeader
		expectViolation bool
	}

	tests := []testCase{
		{
			name: "latest behind finalized with hash mismatch (RPC inconsistent)",
			setup: func(svc *ReorgDetectorService) {
				svc.tailBlocks = map[uint64]protocol.BlockHeader{
					100: {Number: 100, Hash: protocol.Bytes32{0x64}},
				}
				svc.latestFinalizedBlock = 100
			},
			latest: &protocol.BlockHeader{
				Number: 99,
				Hash:   protocol.Bytes32{0x63},
			},
			finalized: &protocol.BlockHeader{
				Number: 100,
				Hash:   protocol.Bytes32{0x64},
			},
			expectViolation: true,
		},
		{
			name: "latest behind finalized but consistent with tail (no violation)",
			setup: func(svc *ReorgDetectorService) {
				svc.tailBlocks = map[uint64]protocol.BlockHeader{
					99:  {Number: 99, Hash: protocol.Bytes32{0x63}},
					100: {Number: 100, Hash: protocol.Bytes32{0x64}},
				}
				svc.latestFinalizedBlock = 100
			},
			latest: &protocol.BlockHeader{
				Number: 99,
				Hash:   protocol.Bytes32{0x63},
			},
			finalized: &protocol.BlockHeader{
				Number: 100,
				Hash:   protocol.Bytes32{0x64},
			},
			expectViolation: false,
		},
		{
			name: "finalized went backwards with hash mismatch",
			setup: func(svc *ReorgDetectorService) {
				svc.latestFinalizedBlock = 110
				svc.tailBlocks = map[uint64]protocol.BlockHeader{
					100: {Number: 100, Hash: protocol.Bytes32{0x64}},
					110: {Number: 110, Hash: protocol.Bytes32{0x6e}},
				}
			},
			latest: &protocol.BlockHeader{
				Number: 111,
				Hash:   protocol.Bytes32{0x6f},
			},
			finalized: &protocol.BlockHeader{
				Number: 100,
				Hash:   protocol.Bytes32{0xaa}, // different from stored
			},
			expectViolation: true,
		},
		{
			name: "finalized advanced and exists in tail with hash mismatch",
			setup: func(svc *ReorgDetectorService) {
				svc.latestFinalizedBlock = 100
				svc.tailBlocks = map[uint64]protocol.BlockHeader{
					101: {Number: 101, Hash: protocol.Bytes32{0x65}},
				}
			},
			latest: &protocol.BlockHeader{
				Number: 105,
				Hash:   protocol.Bytes32{0x69},
			},
			finalized: &protocol.BlockHeader{
				Number: 101,
				Hash:   protocol.Bytes32{0xaa}, // mismatching stored
			},
			expectViolation: true,
		},
		{
			name: "finalized advanced but not in tail yet (no violation)",
			setup: func(svc *ReorgDetectorService) {
				svc.latestFinalizedBlock = 100
				svc.tailBlocks = map[uint64]protocol.BlockHeader{
					100: {Number: 100, Hash: protocol.Bytes32{0x64}},
				}
			},
			latest: &protocol.BlockHeader{
				Number: 105,
				Hash:   protocol.Bytes32{0x69},
			},
			finalized: &protocol.BlockHeader{
				Number: 101,
				Hash:   protocol.Bytes32{0x65},
			},
			expectViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewReorgDetectorService(mockSR, config, lggr)
			require.NoError(t, err)

			tt.setup(svc)

			got := svc.isFinalityViolated(tt.latest, tt.finalized)
			assert.Equal(t, tt.expectViolation, got)
		})
	}
}

func TestGetLongestConsecutiveChain_TableDriven(t *testing.T) {
	lggr := logger.Test(t)
	mockSR := protocol_mocks.NewMockSourceReader(t)

	config := ReorgDetectorConfig{ChainSelector: 1337}
	svc, err := NewReorgDetectorService(mockSR, config, lggr)
	require.NoError(t, err)

	type testCase struct {
		name     string
		blocks   map[uint64]protocol.BlockHeader
		start    uint64
		end      uint64
		wantNums []uint64
	}

	// Helper to build a valid linear block header with predictable hashes.
	makeHeader := func(num uint64, parentHash protocol.Bytes32) protocol.BlockHeader {
		return protocol.BlockHeader{
			Number:     num,
			Hash:       protocol.Bytes32{byte(num)},
			ParentHash: parentHash,
			Timestamp:  time.Now(),
		}
	}

	tests := []testCase{
		{
			name:  "fully consecutive chain (no reorg)",
			start: 100,
			end:   103,
			blocks: func() map[uint64]protocol.BlockHeader {
				m := make(map[uint64]protocol.BlockHeader)
				var zero protocol.Bytes32
				m[100] = makeHeader(100, zero)
				m[101] = makeHeader(101, m[100].Hash)
				m[102] = makeHeader(102, m[101].Hash)
				m[103] = makeHeader(103, m[102].Hash)
				return m
			}(),
			wantNums: []uint64{100, 101, 102, 103},
		},
		{
			name:  "mid-fetch reorg at 103 (wrong parent)",
			start: 100,
			end:   103,
			blocks: func() map[uint64]protocol.BlockHeader {
				m := make(map[uint64]protocol.BlockHeader)
				var zero protocol.Bytes32
				m[100] = makeHeader(100, zero)
				m[101] = makeHeader(101, m[100].Hash)
				m[102] = makeHeader(102, m[101].Hash)
				// wrong parent for 103 -> should cut here
				m[103] = protocol.BlockHeader{
					Number:     103,
					Hash:       protocol.Bytes32{0xFF},
					ParentHash: protocol.Bytes32{0xAA}, // not m[102].Hash
					Timestamp:  time.Now(),
				}
				return m
			}(),
			wantNums: []uint64{100, 101, 102},
		},
		{
			name:  "missing first block (start not present)",
			start: 100,
			end:   103,
			blocks: func() map[uint64]protocol.BlockHeader {
				m := make(map[uint64]protocol.BlockHeader)
				var zero protocol.Bytes32
				// 100 is missing
				m[101] = makeHeader(101, zero)
				m[102] = makeHeader(102, m[101].Hash)
				return m
			}(),
			wantNums: []uint64{}, // no first block -> returns empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svc.getLongestConsecutiveChain(tt.blocks, tt.start, tt.end)
			require.Equal(t, len(tt.wantNums), len(got), "length mismatch")

			for _, num := range tt.wantNums {
				_, ok := got[num]
				assert.Truef(t, ok, "expected block %d in valid chain", num)
			}
		})
	}
}

func TestFillMissingAndValidate_ReorgDetectedAndNotified(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()
	mockSR := protocol_mocks.NewMockSourceReader(t)

	config := ReorgDetectorConfig{ChainSelector: 1337}
	svc, err := NewReorgDetectorService(mockSR, config, lggr)
	require.NoError(t, err)

	// Existing tail: blocks 100-105 on "chain A"
	// Hash = {byte(i)}, ParentHash = {byte(i-1)}
	svc.tailBlocks = make(map[uint64]protocol.BlockHeader)
	for i := uint64(100); i <= 105; i++ {
		parent := protocol.Bytes32{}
		if i > 100 {
			parent = protocol.Bytes32{byte(i - 1)}
		}
		svc.tailBlocks[i] = protocol.BlockHeader{
			Number:     i,
			Hash:       protocol.Bytes32{byte(i)},
			ParentHash: parent,
			Timestamp:  time.Now(),
		}
	}
	svc.latestFinalizedBlock = 100
	svc.latestBlock = 105

	// New canonical chain ("chain B") from 100 to 108:
	// 100,101 share hashes with chain A, diverge at 102.
	rawFetched := make(map[uint64]protocol.BlockHeader)

	// 100,101 same as existing tail (LCA should be 101)
	rawFetched[100] = svc.tailBlocks[100]
	rawFetched[101] = svc.tailBlocks[101]
	rawFetched[102] = svc.tailBlocks[102]

	// Diverge at 102 and beyond on a different fork
	forkStart := uint64(103)
	forkEnd := uint64(108)

	prev := rawFetched[101] // last shared ancestor

	hash := byte(150) // arbitrary different base for new fork
	for i := forkStart; i <= forkEnd; i++ {
		rawFetched[i] = protocol.BlockHeader{
			Number:     i,
			Hash:       protocol.Bytes32{hash},
			ParentHash: prev.Hash,
			Timestamp:  time.Now(),
		}
		prev = rawFetched[i]
		hash++
	}

	// Mock GetBlocksHeaders to return "rawFetched" for whatever range we ask [100,108].
	mockSR.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			res := make(map[*big.Int]protocol.BlockHeader)
			for _, bn := range blockNumbers {
				n := bn.Uint64()
				b, ok := rawFetched[n]
				if ok {
					res[bn] = b
				}
			}
			return res, nil
		})

	// latest and finalized we pass into fillMissingAndValidate directly
	latest := protocol.BlockHeader{Number: 108, Hash: rawFetched[108].Hash}
	finalized := &protocol.BlockHeader{Number: 100, Hash: rawFetched[100].Hash}

	// Run reorg detection logic.
	go svc.fillMissingAndValidate(ctx, latest, finalized)

	// Expect a reorg notification with LCA = 101.
	status := <-svc.statusCh
	assert.Equal(t, protocol.ReorgTypeNormal, status.Type)
	assert.Equal(t, uint64(102), status.ResetToBlock)
}

func TestFillMissingAndValidate_MidFetchReorgTriggersNotification(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()
	mockSR := protocol_mocks.NewMockSourceReader(t)

	config := ReorgDetectorConfig{ChainSelector: 1337}
	svc, err := NewReorgDetectorService(mockSR, config, lggr)
	require.NoError(t, err)

	// Existing tail: 100–107, linear chain A
	svc.tailBlocks = make(map[uint64]protocol.BlockHeader)
	var prevHash protocol.Bytes32
	for i := uint64(100); i <= 107; i++ {
		hash := protocol.Bytes32{byte(i)}
		svc.tailBlocks[i] = protocol.BlockHeader{
			Number:     i,
			Hash:       hash,
			ParentHash: prevHash,
			Timestamp:  time.Now(),
		}
		prevHash = hash
	}
	svc.latestFinalizedBlock = 100
	svc.latestBlock = 107

	// Raw fetched blocks from 100 to 110.
	// 100–107: consistent with tail.
	// 108: wrong parent -> mid-fetch reorg.
	rawFetched := make(map[uint64]protocol.BlockHeader)

	for i := uint64(100); i <= 107; i++ {
		rawFetched[i] = svc.tailBlocks[i]
	}

	rawFetched[108] = protocol.BlockHeader{
		Number:     108,
		Hash:       protocol.Bytes32{0xAA},
		ParentHash: protocol.Bytes32{0xFF}, // incorrect parent
		Timestamp:  time.Now(),
	}

	for i := uint64(109); i <= 110; i++ {
		rawFetched[i] = protocol.BlockHeader{
			Number:     i,
			Hash:       protocol.Bytes32{byte(0xAA + (i - 108))},
			ParentHash: rawFetched[i-1].Hash,
			Timestamp:  time.Now(),
		}
	}

	latest := protocol.BlockHeader{
		Number: 110,
		Hash:   rawFetched[110].Hash,
	}
	finalized := &protocol.BlockHeader{
		Number: 100,
		Hash:   rawFetched[100].Hash,
	}

	mockSR.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			res := make(map[*big.Int]protocol.BlockHeader)
			for _, bn := range blockNumbers {
				n := bn.Uint64()
				if b, ok := rawFetched[n]; ok {
					res[bn] = b
				}
			}
			return res, nil
		})

	go svc.fillMissingAndValidate(ctx, latest, finalized)

	status := <-svc.statusCh
	assert.Equal(t, protocol.ReorgTypeNormal, status.Type)
	assert.Equal(t, uint64(107), status.ResetToBlock) // last valid block, reorg starts after 107
}
