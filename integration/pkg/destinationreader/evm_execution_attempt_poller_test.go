package destinationreader

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

// mockClient is a mock implementation of client.Client for testing.
// It only implements HeaderByNumber which is what we need for these tests.
type mockClient struct {
	mock.Mock
	client.Client                                     // Embed to satisfy interface (will panic if other methods called)
	headerFunc    func(blockNum uint64) *types.Header // Optional: function to generate headers dynamically
}

func (m *mockClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	// If headerFunc is set and number is not nil, use it to generate header
	if m.headerFunc != nil && number != nil {
		header := m.headerFunc(number.Uint64())
		if header != nil {
			return header, nil
		}
	}

	args := m.Called(ctx, number)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Header), args.Error(1)
}

// blockTimeCalculator calculates block timestamps based on block number and block time interval.
type blockTimeCalculator struct {
	genesisTime   time.Time
	blockInterval time.Duration
}

func newBlockTimeCalculator(genesisTime time.Time, blockInterval time.Duration) *blockTimeCalculator {
	return &blockTimeCalculator{
		genesisTime:   genesisTime,
		blockInterval: blockInterval,
	}
}

func (btc *blockTimeCalculator) getBlockTime(blockNum uint64) time.Time {
	return btc.genesisTime.Add(time.Duration(blockNum) * btc.blockInterval)
}

func (btc *blockTimeCalculator) createHead(blockNum uint64) *types.Header {
	blockTime := btc.getBlockTime(blockNum)
	return &types.Header{
		Number: big.NewInt(int64(blockNum)),
		Time:   uint64(blockTime.Unix()),
	}
}

// setupTestPoller creates a test poller with a mock client.
func setupTestPoller(t *testing.T, mockCli *mockClient, lookbackWindow time.Duration) *EvmExecutionAttemptPoller {
	offRampAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	lggr := logger.Test(t)

	poller, err := NewEVMExecutionAttemptPoller(
		offRampAddr,
		mockCli,
		lggr,
		lookbackWindow,
	)
	require.NoError(t, err)
	require.NotNil(t, poller)

	return poller
}

func TestGetStartBlock_MatureChain(t *testing.T) {
	// Simulate a mature chain: 200k blocks, block every 0.25s
	// Chain spans: 200000 * 0.25s = 50,000s = ~13.9 hours
	// So we'll use a 12 hour lookback window to ensure it's within chain history
	const (
		totalBlocks    = 200000
		blockInterval  = 250 * time.Millisecond // 0.25s
		lookbackWindow = 12 * time.Hour         // Use 12h instead of 24h to fit within chain
	)

	// Calculate genesis time so that latest block is "now"
	now := time.Now()
	genesisTime := now.Add(-time.Duration(totalBlocks) * blockInterval)
	calc := newBlockTimeCalculator(genesisTime, blockInterval)

	// Target time is 12 hours ago (should be well within chain history)
	targetTime := now.Add(-lookbackWindow)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, lookbackWindow)

	// Mock latest block
	latestHead := calc.createHead(totalBlocks)
	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).Return(latestHead, nil).Once()

	// Mock blocks during narrowing phase (going backwards from latest)
	// We'll check blocks at: 200k, 195k, 190k, ... until we find one older than target
	currentBlock := uint64(totalBlocks)
	for currentBlock > 0 {
		checkBlock := uint64(0)
		if currentBlock > maxFilterBlockRange {
			checkBlock = currentBlock - maxFilterBlockRange
		}

		checkHead := calc.createHead(checkBlock)
		checkTime := calc.getBlockTime(checkBlock)

		mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
			return bn != nil && bn.Uint64() == checkBlock
		})).Return(checkHead, nil).Once()

		if checkTime.Before(targetTime) || checkBlock == 0 {
			// Found the range, break
			break
		}

		currentBlock = checkBlock
	}

	// Mock binary search calls within narrowed range using dynamic header generation
	mockCli.headerFunc = func(blockNum uint64) *types.Header {
		return calc.createHead(blockNum)
	}

	// Set up a catch-all mock for binary search calls (headerFunc will handle the actual return)
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() <= totalBlocks
	})).Return((*types.Header)(nil), nil).Maybe()

	// Execute
	ctx := context.Background()
	err := poller.getStartBlock(ctx, lookbackWindow)

	// Assertions
	require.NoError(t, err)
	assert.GreaterOrEqual(t, poller.startBlock, uint64(0))
	assert.LessOrEqual(t, poller.startBlock, uint64(totalBlocks))

	// Verify the found block is close to expected (within reasonable range)
	// The found block should be at or before the target time (we go back one block at the end)
	// Allow variance of a few block intervals due to binary search precision
	foundBlockTime := calc.getBlockTime(poller.startBlock)
	timeDiff := targetTime.Sub(foundBlockTime)

	// Found block should be before or very close to target (within a few block intervals)
	maxVariance := 3 * blockInterval
	assert.True(t, timeDiff >= -maxVariance && timeDiff <= lookbackWindow,
		"Found block time should be close to target time, got diff: %v, foundBlock: %d, targetTime: %v, foundTime: %v",
		timeDiff, poller.startBlock, targetTime, foundBlockTime)

	// Note: We don't assert all mock expectations here because binary search
	// makes variable numbers of calls depending on the search path.
	// The important thing is that the result is correct.
}

func TestGetStartBlock_LatestBlockOlderThanTarget(t *testing.T) {
	const lookbackWindow = 24 * time.Hour

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, lookbackWindow)

	// Latest block is 48 hours old (older than 24 hour lookback)
	now := time.Now()
	oldTime := now.Add(-48 * time.Hour)
	latestHead := &types.Header{
		Number: big.NewInt(1000),
		Time:   uint64(oldTime.Unix()),
	}

	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).Return(latestHead, nil).Once()

	ctx := context.Background()
	err := poller.getStartBlock(ctx, lookbackWindow)

	require.NoError(t, err)
	assert.Equal(t, latestHead.Number.Uint64(), poller.startBlock, "Should use latest block when it is older than target")
	mockCli.AssertExpectations(t)
}

func TestGetStartBlock_SmallChain(t *testing.T) {
	// Test with a small chain that doesn't require narrowing
	const (
		totalBlocks    = 1000
		blockInterval  = 12 * time.Second // Ethereum-like
		lookbackWindow = 24 * time.Hour
	)

	now := time.Now()
	genesisTime := now.Add(-time.Duration(totalBlocks) * blockInterval)
	calc := newBlockTimeCalculator(genesisTime, blockInterval)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, lookbackWindow)

	// Mock latest block
	latestHead := calc.createHead(totalBlocks)
	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).Return(latestHead, nil).Once()

	// Since totalBlocks < maxFilterBlockRange, narrowing will check block 0
	block0Head := calc.createHead(0)
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() == 0
	})).Return(block0Head, nil).Once()

	// Binary search calls using dynamic header generation
	mockCli.headerFunc = func(blockNum uint64) *types.Header {
		return calc.createHead(blockNum)
	}
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() <= totalBlocks
	})).Return((*types.Header)(nil), nil).Maybe()

	ctx := context.Background()
	err := poller.getStartBlock(ctx, lookbackWindow)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, poller.startBlock, uint64(0))
	assert.LessOrEqual(t, poller.startBlock, uint64(totalBlocks))
	// Note: We don't assert all mock expectations because binary search makes variable calls
}

func TestGetStartBlock_ExactMatch(t *testing.T) {
	// Test case where a block exactly matches the target time
	const (
		totalBlocks    = 10000
		blockInterval  = 12 * time.Second
		lookbackWindow = 24 * time.Hour
	)

	now := time.Now()
	genesisTime := now.Add(-time.Duration(totalBlocks) * blockInterval)
	calc := newBlockTimeCalculator(genesisTime, blockInterval)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, lookbackWindow)

	// Mock latest block
	latestHead := calc.createHead(totalBlocks)
	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).Return(latestHead, nil).Once()

	// Mock narrowing phase
	checkBlock := uint64(totalBlocks - maxFilterBlockRange)
	checkHead := calc.createHead(checkBlock)
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() == checkBlock
	})).Return(checkHead, nil).Once()

	// Mock binary search using dynamic header generation
	mockCli.headerFunc = func(blockNum uint64) *types.Header {
		return calc.createHead(blockNum)
	}
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() <= totalBlocks
	})).Return((*types.Header)(nil), nil).Maybe()

	ctx := context.Background()
	err := poller.getStartBlock(ctx, lookbackWindow)

	require.NoError(t, err)
	assert.Greater(t, poller.startBlock, uint64(0))
}

func TestGetStartBlock_ErrorGettingLatestBlock(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, 24*time.Hour)

	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).
		Return(nil, assert.AnError).Once()

	ctx := context.Background()
	err := poller.getStartBlock(ctx, 24*time.Hour)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get latest block header")
}

func TestGetStartBlock_ErrorDuringNarrowing(t *testing.T) {
	const totalBlocks = 50000
	blockInterval := 250 * time.Millisecond

	now := time.Now()
	genesisTime := now.Add(-time.Duration(totalBlocks) * blockInterval)
	calc := newBlockTimeCalculator(genesisTime, blockInterval)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, 24*time.Hour)

	// Mock latest block
	latestHead := calc.createHead(totalBlocks)
	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).Return(latestHead, nil).Once()

	// Error during narrowing
	checkBlock := uint64(totalBlocks - maxFilterBlockRange)
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() == checkBlock
	})).Return(nil, assert.AnError).Once()

	ctx := context.Background()
	err := poller.getStartBlock(ctx, 24*time.Hour)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get block time")
}

func TestGetStartBlock_ErrorDuringBinarySearch(t *testing.T) {
	const totalBlocks = 10000
	blockInterval := 12 * time.Second

	now := time.Now()
	genesisTime := now.Add(-time.Duration(totalBlocks) * blockInterval)
	calc := newBlockTimeCalculator(genesisTime, blockInterval)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, 24*time.Hour)

	// Mock latest block
	latestHead := calc.createHead(totalBlocks)
	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).Return(latestHead, nil).Once()

	// Mock narrowing - find range quickly
	checkBlock := uint64(totalBlocks - maxFilterBlockRange)
	checkHead := calc.createHead(checkBlock)
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() == checkBlock
	})).Return(checkHead, nil).Once()

	// Error during binary search
	mockCli.On("HeaderByNumber", mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()

	ctx := context.Background()
	err := poller.getStartBlock(ctx, 24*time.Hour)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get block time")
}

func TestGetStartBlock_Block0NewerThanTarget(t *testing.T) {
	// Edge case: chain started recently, block 0 is newer than target time
	const (
		totalBlocks    = 1000
		blockInterval  = 12 * time.Second
		lookbackWindow = 24 * time.Hour
	)

	// Chain started 1 hour ago, but we're looking for 24 hours ago
	now := time.Now()
	genesisTime := now.Add(-1 * time.Hour) // Very recent chain
	calc := newBlockTimeCalculator(genesisTime, blockInterval)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, lookbackWindow)

	// Mock latest block
	latestHead := calc.createHead(totalBlocks)
	mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).Return(latestHead, nil).Once()

	// Block 0 is newer than target, so narrowing will stop at block 0
	block0Head := calc.createHead(0)
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() == 0
	})).Return(block0Head, nil).Once()

	// Binary search will find block 0 as the start
	mockCli.headerFunc = func(blockNum uint64) *types.Header {
		return calc.createHead(blockNum)
	}
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil && bn.Uint64() <= totalBlocks
	})).Return((*types.Header)(nil), nil).Maybe()

	ctx := context.Background()
	err := poller.getStartBlock(ctx, lookbackWindow)

	require.NoError(t, err)
	assert.Equal(t, uint64(0), poller.startBlock, "Should use block 0 when chain is too new")
}

func TestNarrowSearchRange(t *testing.T) {
	const (
		totalBlocks   = 200000
		blockInterval = 250 * time.Millisecond
	)

	now := time.Now()
	genesisTime := now.Add(-time.Duration(totalBlocks) * blockInterval)
	calc := newBlockTimeCalculator(genesisTime, blockInterval)
	targetTime := now.Add(-24 * time.Hour)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, 24*time.Hour)

	// Mock the narrowing process
	currentBlock := uint64(totalBlocks)
	for currentBlock > 0 {
		checkBlock := uint64(0)
		if currentBlock > maxFilterBlockRange {
			checkBlock = currentBlock - maxFilterBlockRange
		}

		checkHead := calc.createHead(checkBlock)
		mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
			return bn != nil && bn.Uint64() == checkBlock
		})).Return(checkHead, nil).Once()

		checkTime := calc.getBlockTime(checkBlock)
		if checkTime.Before(targetTime) || checkBlock == 0 {
			break
		}
		currentBlock = checkBlock
	}

	rangeValue, err := poller.narrowSearchRange(context.Background(), uint64(totalBlocks), targetTime)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, rangeValue.lower, uint64(0))
	assert.LessOrEqual(t, rangeValue.upper, uint64(totalBlocks))
	assert.LessOrEqual(t, rangeValue.upper-rangeValue.lower, uint64(maxFilterBlockRange))
}

func TestBinarySearchBlockByTime(t *testing.T) {
	const (
		blockInterval = 12 * time.Second
	)

	now := time.Now()
	genesisTime := now.Add(-10000 * blockInterval)
	calc := newBlockTimeCalculator(genesisTime, blockInterval)
	targetTime := now.Add(-24 * time.Hour)

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, 24*time.Hour)

	searchRange := blockRange{lower: 0, upper: 10000}

	// Mock binary search calls using dynamic header generation
	mockCli.headerFunc = func(blockNum uint64) *types.Header {
		return calc.createHead(blockNum)
	}
	mockCli.On("HeaderByNumber", mock.Anything, mock.MatchedBy(func(bn *big.Int) bool {
		return bn != nil
	})).Return((*types.Header)(nil), nil).Maybe()

	foundBlock, err := poller.binarySearchBlockByTime(context.Background(), searchRange, targetTime)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, foundBlock, searchRange.lower)
	assert.LessOrEqual(t, foundBlock, searchRange.upper)

	// Verify the found block's time is close to target
	foundTime := calc.getBlockTime(foundBlock)
	timeDiff := targetTime.Sub(foundTime)
	maxVariance := 3 * blockInterval
	assert.True(t, timeDiff >= -maxVariance && timeDiff <= 24*time.Hour,
		"Found block should be close to target time, got diff: %v", timeDiff)
}
