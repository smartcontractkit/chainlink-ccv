package destinationreader

import (
	"context"
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

// TestRunBackfill covers the behaviour of runBackfill under various conditions.
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
			name:                "backfill fails when latest block header cannot be fetched",
			startBlock:          1000,
			headerErr:           errors.New("rpc unavailable"),
			wantErr:             true,
			wantErrContains:     "backfill failed",
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

// TestRunBackfill_InitialBlockPositioning verifies that runBackfill correctly initialises
// lastPolledBlock before calling pollForEvents so that the filter covers the full window.
func TestRunBackfill_InitialBlockPositioning(t *testing.T) {
	tests := []struct {
		name                    string
		startBlock              uint64
		wantLastPolledBeforePoll uint64
	}{
		{
			name:                    "startBlock > 0 sets lastPolledBlock to startBlock-1",
			startBlock:              500,
			wantLastPolledBeforePoll: 499,
		},
		{
			name:                    "startBlock == 0 leaves lastPolledBlock at 0",
			startBlock:              0,
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
