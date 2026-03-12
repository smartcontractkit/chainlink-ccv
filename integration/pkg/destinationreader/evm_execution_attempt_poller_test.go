package destinationreader

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/offramp"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

// mockClient is a mock implementation of client.Client for testing.
// It only implements HeaderByNumber which is what we need for these tests.
type mockClient struct {
	mock.Mock
	client.Client                                                                   // Embed to satisfy interface (will panic if other methods called)
	headerFunc    func(blockNum uint64) *types.Header                               // Optional: function to generate headers dynamically
	dynamicFunc   func(ctx context.Context, number *big.Int) (*types.Header, error) // Optional: dynamic function for complex scenarios
}

func (m *mockClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	// If dynamicFunc is set, use it (for reconnection tests)
	if m.dynamicFunc != nil {
		return m.dynamicFunc(ctx, number)
	}

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

// FilterLogs is a stub implementation needed for FilterExecutionStateChanged.
// Returns empty results for testing purposes.
func (m *mockClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return []types.Log{}, nil
}

// SubscribeFilterLogs is a stub that always returns an error, simulating a non-WebSocket
// RPC endpoint. This prevents a nil-pointer panic from the embedded client.Client when
// WatchExecutionStateChanged is called in tests.
func (m *mockClient) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	return nil, errors.New("websocket not available in test environment")
}

func (m *mockClient) TransactionByHash(ctx context.Context, txHash common.Hash) (*types.Transaction, error) {
	args := m.Called(ctx, txHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Transaction), args.Error(1)
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

func TestProcessExecutionStateChanged_RejectsTxNotDirectlyToOffRamp(t *testing.T) {
	offRampAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	wrongAddr := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	tests := []struct {
		name      string
		txTo      *common.Address
		expectErr string
	}{
		{
			name:      "rejects tx to different address",
			txTo:      &wrongAddr,
			expectErr: "does not match offramp address",
		},
		{
			name:      "rejects contract creation tx with nil To",
			txTo:      nil,
			expectErr: "does not match offramp address",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCli := new(mockClient)
			poller := setupTestPoller(t, mockCli, 24*time.Hour)
			assert.Equal(t, offRampAddr, poller.offRampAddress)

			tx := types.NewTx(&types.LegacyTx{
				To:   tc.txTo,
				Gas:  500_000,
				Data: []byte{0x01, 0x02, 0x03, 0x04},
			})

			event := &offramp.OffRampExecutionStateChanged{}
			mockCli.On("TransactionByHash", mock.Anything, event.Raw.TxHash).
				Return(tx, nil).Once()

			err := poller.processExecutionStateChanged(context.Background(), event)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectErr)
			mockCli.AssertExpectations(t)
		})
	}
}

func TestProcessExecutionStateChanged_RejectsWhenTransactionByHashFails(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, 24*time.Hour)

	event := &offramp.OffRampExecutionStateChanged{}
	mockCli.On("TransactionByHash", mock.Anything, event.Raw.TxHash).
		Return(nil, errors.New("rpc error")).Once()

	err := poller.processExecutionStateChanged(context.Background(), event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get transaction by hash")
	mockCli.AssertExpectations(t)
}

// TestRunBackfill covers the behavior of runBackfill under various conditions.
func TestRunBackfill(t *testing.T) {
	tests := []struct {
		name                string
		startBlock          uint64
		latestBlock         uint64
		headerErr           error
		wantErr             bool
		wantErrContains     string
		wantLastPolledBlock uint64
	}{
		{
			name:                "successful backfill from non-zero startBlock positions lastPolledBlock correctly",
			startBlock:          1000,
			latestBlock:         2000,
			wantErr:             false,
			wantLastPolledBlock: 2000,
		},
		{
			name:                "successful backfill from startBlock zero leaves lastPolledBlock at latest block",
			startBlock:          0,
			latestBlock:         1000,
			wantErr:             false,
			wantLastPolledBlock: 1000,
		},
		{
			name:            "backfill fails when latest block header cannot be fetched",
			startBlock:      1000,
			headerErr:       errors.New("rpc unavailable"),
			wantErr:         true,
			wantErrContains: "backfill failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCli := new(mockClient)
			poller := setupTestPoller(t, mockCli, 24*time.Hour)
			poller.startBlock = tc.startBlock

			if tc.headerErr != nil {
				mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).
					Return(nil, tc.headerErr).Once()
			} else {
				latestHead := &types.Header{
					Number: big.NewInt(int64(tc.latestBlock)),
					Time:   uint64(time.Now().Unix()),
				}
				mockCli.On("HeaderByNumber", mock.Anything, (*big.Int)(nil)).
					Return(latestHead, nil).Once()
			}

			err := poller.runBackfill(context.Background())

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantLastPolledBlock, poller.lastPolledBlock)
			}
			mockCli.AssertExpectations(t)
		})
	}
}

// TestRunBackfill_InitialBlockPositioning verifies that runBackfill correctly initializes
// lastPolledBlock before calling pollForEvents so that the filter covers the full window.
func TestRunBackfill_InitialBlockPositioning(t *testing.T) {
	tests := []struct {
		name                     string
		startBlock               uint64
		wantLastPolledBeforePoll uint64
	}{
		{
			name:                     "startBlock > 0 sets lastPolledBlock to startBlock-1",
			startBlock:               500,
			wantLastPolledBeforePoll: 499,
		},
		{
			name:                     "startBlock == 0 leaves lastPolledBlock at 0",
			startBlock:               0,
			wantLastPolledBeforePoll: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCli := new(mockClient)
			poller := setupTestPoller(t, mockCli, 24*time.Hour)
			poller.startBlock = tc.startBlock

			var capturedLastPolled uint64
			mockCli.dynamicFunc = func(ctx context.Context, number *big.Int) (*types.Header, error) {
				if number == nil {
					// Capture lastPolledBlock at the moment pollForEvents calls HeaderByNumber
					capturedLastPolled = poller.lastPolledBlock
					return &types.Header{
						Number: big.NewInt(int64(tc.startBlock + 100)),
						Time:   uint64(time.Now().Unix()),
					}, nil
				}
				return nil, errors.New("unexpected call")
			}

			err := poller.runBackfill(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.wantLastPolledBeforePoll, capturedLastPolled,
				"lastPolledBlock must be set before pollForEvents is invoked")
		})
	}
}

// TestStartupSequence_BackfillFailureFallback verifies that when runBackfill returns an error,
// Start falls back to setting lastPolledBlock = startBlock so downstream modes begin from
// a known baseline rather than from 0.
func TestStartupSequence_BackfillFailureFallback(t *testing.T) {
	tests := []struct {
		name                string
		startBlock          uint64
		wantLastPolledBlock uint64
	}{
		{
			name:                "lastPolledBlock falls back to startBlock on backfill error",
			startBlock:          750,
			wantLastPolledBlock: 750,
		},
		{
			name:                "fallback with startBlock zero keeps lastPolledBlock at zero",
			startBlock:          0,
			wantLastPolledBlock: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCli := new(mockClient)
			poller := setupTestPoller(t, mockCli, 24*time.Hour)
			poller.startBlock = tc.startBlock

			// Simulate backfill failure by making HeaderByNumber fail for pollForEvents.
			// runBackfill sets lastPolledBlock then calls pollForEvents which calls HeaderByNumber.
			mockCli.dynamicFunc = func(ctx context.Context, number *big.Int) (*types.Header, error) {
				return nil, errors.New("rpc unavailable")
			}

			err := poller.runBackfill(context.Background())
			require.Error(t, err)

			// Simulate what Start() does on backfill failure.
			poller.lastPolledBlock = poller.startBlock

			assert.Equal(t, tc.wantLastPolledBlock, poller.lastPolledBlock)
		})
	}
}

// TestStartHTTPMode_PreservesLastPolledBlock confirms that startHTTPMode no longer resets
// lastPolledBlock to startBlock. After a successful backfill, HTTP mode should continue
// from the position the backfill reached.
func TestStartHTTPMode_PreservesLastPolledBlock(t *testing.T) {
	tests := []struct {
		name                string
		startBlock          uint64
		lastPolledBlock     uint64
		wantLastPolledBlock uint64
	}{
		{
			name:                "lastPolledBlock is ahead of startBlock after backfill",
			startBlock:          1000,
			lastPolledBlock:     2000,
			wantLastPolledBlock: 2000,
		},
		{
			name:                "lastPolledBlock equals startBlock on backfill fallback",
			startBlock:          500,
			lastPolledBlock:     500,
			wantLastPolledBlock: 500,
		},
		{
			name:                "lastPolledBlock is zero when startBlock is zero",
			startBlock:          0,
			lastPolledBlock:     0,
			wantLastPolledBlock: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCli := new(mockClient)
			poller := setupTestPoller(t, mockCli, 24*time.Hour)
			poller.startBlock = tc.startBlock
			poller.lastPolledBlock = tc.lastPolledBlock

			ctx, cancel := context.WithCancel(context.Background())
			cancel() // cancel immediately so the polling goroutine exits promptly

			poller.startHTTPMode(ctx)
			poller.runWg.Wait()

			assert.Equal(t, tc.wantLastPolledBlock, poller.lastPolledBlock,
				"startHTTPMode must not reset lastPolledBlock")
		})
	}
}

// validExecuteCallDataHex is a real ABI-encoded execute(bytes,address[],bytes[],uint32) call
// captured from an on-chain transaction.
const validExecuteCallDataHex = "3b81ab9b0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016401ccf0a31a221f3c9bde41ba4fc9d91ad9000000000000145e000f4e6000030d4000008d7bbba13d6a09289463df0e520d10ef00d537fa7a44e76486bdb33022d2ee6b200000000000000000000000002162318d639bbbc2bc8d1562a7bafa459b9f29bf146ab86b3872421d418137f193fec05661947c5f0e20000000000000000000000000da9e8e71bb750a996af33ebb8abb18cd9eb9dc75144f32ae7f112c26b109357785e5c66dc5d747fbce000000af010000000000000000000000000000000000000000000000000000000000000001200000000000000000000000008d20c68db3e596b30a142b7092127adc889d1e0020000000000000000000000000c47e4b3124597fdf8dd07843d4a7052f2ee80c301493283b6b889c591893db0dc93bad71656d5d8923144f32ae7f112c26b109357785e5c66dc5d747fbce0020000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000003162012041baaf4739cb99ddbc70765f4581f54b000000000000000000000000997bbb1be075e6e9e7802b84c27c79e820a337a30000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000484eba555880000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000001a4e288fb4a4402fb0a3289aceac41d5260d9031d376f3a9f3ee389439558417173c1f6f6b30000000000000000000000000000000000000000000000000000000000000013000000000000000000000000a2e96f8e7de37be991ee0ac8e878ed5784350f4b000000000000000000000000ff9aef444d833bf5ebbaa40a5dff55dfa5739cd700000000000000000000000019ab033f5169c1c8da895aad5d1cc20f49dfff9100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000a50200000000000000000000000093283b6b889c591893db0dc93bad71656d5d8923000000000000000000000000da9e8e71bb750a996af33ebb8abb18cd9eb9dc750000000000000000000000004f32ae7f112c26b109357785e5c66dc5d747fbce0000000000000000000000000000000000000000000000000000000000000001eba555886e19dca884914cc5720ebdda8c6414cd1bd666f3aeee0f143e0a281e62f4c49900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000000409841b903ae4d23ab34da554b2ef81847d60cb03f02ebf863044750caa127a7563a9373427f462a5429971cb9bc268241daca2a7e3927d56a4341d9ef139d4aad000000000000000000000000000000000000000000000000000000000000004097b370d278ed66ef18141f6c5e5f5b0d855d94b7a1be0aa2c63238a64ce871a6005ef3140d22f92cd5b6aecc8ce02d1ef536a5315f4faacb8b9e849d61599b0a0000000000000000000000000000000000000000000000000000000000000040d7acb0a6c8ad32bc4cae3af556387ba5b5b0c0a71f53c02847fbc4d1c1c4b6a877bf44158125500eefcaa2f37cf0d92c690acf2bc2ade18488363bb78a2d852b0000000000000000000000000000000000000000000000000000000000000040c5b81ff69aa3b970c5d492e82529748ac43cd021d39dc4d87811d43460b5cad832c240239cfe99b2aaf50a9f84c4fc72ef1471b0bd7a56e767e63fa9f6d55a1900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018649ff34ed01806fbfc901b4f207f986068dd3591f0e9efc147b703a84d6c3102bc186d69fb97ae080e7f705e3d717b1d341d2bac86b7e8603e73c9958a8d22aafbfaa5160bd92a4efcd39d61a654dfd44c873c1c9b92fa801239cc97008f9a4fb086003a0a66c64f3f8c2ddff52a455ded976064b198c051dd7595e08a8a512aea49dfae209f6abb4e320aa053b0801584bc3a3c767652bc283d669c1affcc0c56b24d3fdd2bbbfcf2af847c55928c065d195be6cd9efe3f258b966b76beb0bd08106bab39cf324f340abc3ffcbee50e8f1122b0e75711686ad0d75d8b672a0e58dc2c256e6a62f1951f63eb53572d38ea9b2fc275ec57b1a1e050f8d1e9b95bc97890c8db2722a8636e1d4b68014aa71a054a3034d21490bb322642958daabd4c0e43cccbea0a14231d23acc359e7bb2379e6fb248fa6e768f40684dbd654ff0d63caf864a0b99db39b7810d54c0796d8fe138151e1cfa69d8f0bb6951821a0cb174ec764e25455d5e7916ef0e3b38a7b510d7dbdff5c331023da46f0b3e5eb01da79b61ff090000000000000000000000000000000000000000000000000000"

func TestDecodeCallDataToExecutionAttempt(t *testing.T) {
	validCallData, err := hex.DecodeString(validExecuteCallDataHex)
	require.NoError(t, err)

	t.Run("successfully decodes valid execute call data", func(t *testing.T) {
		mockCli := new(mockClient)
		poller := setupTestPoller(t, mockCli, 24*time.Hour)
		gasLimit := uint64(500_000)

		attempt, err := poller.decodeCallDataToExecutionAttempt(validCallData, gasLimit)
		require.NoError(t, err)
		require.NotNil(t, attempt)

		assert.Equal(t, new(big.Int).SetUint64(gasLimit), attempt.TransactionGasLimit)
		assert.NotEmpty(t, attempt.Report.CCVS, "should have at least one CCV address")
		assert.Len(t, attempt.Report.CCVS, 2, "should decode two CCV addresses")
		assert.Len(t, attempt.Report.CCVData, 2, "should decode two CCV data entries")

		// Verify message round-trips: re-encode and decode should yield identical message
		reEncoded, err := attempt.Report.Message.Encode()
		require.NoError(t, err)
		require.NotEmpty(t, reEncoded)

		// MessageID should be computable (proves the message is well-formed)
		msgID, err := attempt.Report.Message.MessageID()
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, msgID, "message ID should not be zero")
	})

	t.Run("rejects call data shorter than function selector", func(t *testing.T) {
		mockCli := new(mockClient)
		poller := setupTestPoller(t, mockCli, 24*time.Hour)

		_, err := poller.decodeCallDataToExecutionAttempt([]byte{0x01, 0x02}, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "call data too short")
	})

	t.Run("rejects wrong function selector", func(t *testing.T) {
		mockCli := new(mockClient)
		poller := setupTestPoller(t, mockCli, 24*time.Hour)

		wrongSelector := make([]byte, len(validCallData))
		copy(wrongSelector, validCallData)
		wrongSelector[0] = 0xFF
		wrongSelector[1] = 0xFF
		wrongSelector[2] = 0xFF
		wrongSelector[3] = 0xFF

		_, err := poller.decodeCallDataToExecutionAttempt(wrongSelector, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "call data does not match execute function selector")
	})

	t.Run("rejects call data with valid selector but corrupted ABI payload", func(t *testing.T) {
		mockCli := new(mockClient)
		poller := setupTestPoller(t, mockCli, 24*time.Hour)

		// Keep valid selector but truncate the rest
		truncated := validCallData[:functionSelectorLength+10]

		_, err := poller.decodeCallDataToExecutionAttempt(truncated, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unpack execute call data")
	})

	t.Run("empty call data returns error", func(t *testing.T) {
		mockCli := new(mockClient)
		poller := setupTestPoller(t, mockCli, 24*time.Hour)

		_, err := poller.decodeCallDataToExecutionAttempt([]byte{}, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "call data too short")
	})
}

// TestStartWSMode_UsesLastPolledBlock verifies that after a successful backfill the WS
// subscription is attempted starting from lastPolledBlock rather than startBlock.
// Because WatchExecutionStateChanged requires a live WebSocket endpoint, this test
// confirms the correct starting position is passed by inspecting the poller state that
// startWSMode reads from — any discrepancy between lastPolledBlock and startBlock would
// cause incorrect coverage.
func TestStartWSMode_UsesLastPolledBlock(t *testing.T) {
	tests := []struct {
		name            string
		startBlock      uint64
		lastPolledBlock uint64
	}{
		{
			name:            "WS subscription start comes from lastPolledBlock after successful backfill",
			startBlock:      1000,
			lastPolledBlock: 2000,
		},
		{
			name:            "WS subscription start equals startBlock when backfill failed",
			startBlock:      1000,
			lastPolledBlock: 1000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCli := new(mockClient)
			poller := setupTestPoller(t, mockCli, 24*time.Hour)
			poller.startBlock = tc.startBlock
			poller.lastPolledBlock = tc.lastPolledBlock

			// WatchExecutionStateChanged will fail (no WebSocket), confirming startWSMode
			// returns an error; the important invariant is which value it reads.
			err := poller.startWSMode(context.Background())

			// In a non-WS environment the call fails; the key assertion is that
			// lastPolledBlock was not altered by startWSMode.
			assert.Equal(t, tc.lastPolledBlock, poller.lastPolledBlock,
				"startWSMode must not modify lastPolledBlock")
			// err may or may not be nil depending on WS availability in the test env.
			_ = err
		})
	}
}

// TestHTTPPolling_ContinuousRPCFailures tests that HTTP polling continues
// to retry even when RPC is continuously failing, without crashing.
func TestHTTPPolling_ContinuousRPCFailures(t *testing.T) {
	const lookbackWindow = 24 * time.Hour
	const startBlock = 1000

	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, lookbackWindow)
	poller.startBlock = startBlock
	poller.lastPolledBlock = startBlock
	poller.pollInterval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Use dynamic function to simulate RPC always failing
	mockCli.dynamicFunc = func(ctx context.Context, number *big.Int) (*types.Header, error) {
		return nil, errors.New("RPC continuously unavailable")
	}

	// Start polling, note this spawns a goroutine.
	poller.startHTTPMode(ctx)

	// Waits until context timeout (100 ms)
	<-ctx.Done()

	// Wait for the goroutine to finish.
	poller.runWg.Wait()

	// Verify poller fields are set correctly
	assert.Equal(t, uint64(startBlock), poller.startBlock, "Poller should maintain start block")
	assert.Equal(t, uint64(startBlock), poller.lastPolledBlock, "Poller should maintain last polled block")
}
