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

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func floodTestHead(head uint64) func(context.Context, *big.Int) (*types.Header, error) {
	return func(_ context.Context, n *big.Int) (*types.Header, error) {
		num := head
		if n != nil {
			num = n.Uint64()
		}
		return &types.Header{Number: new(big.Int).SetUint64(num), Time: uint64(time.Now().Unix())}, nil
	}
}

// A range the RPC rejects is bisected until it fits, and the poll still reaches head.
func TestPollForEvents_SplitsRangeRejectedByRPC(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	msg := buildPollerTestMessage(t)
	tx := buildExecuteTxForMessage(t, poller.offRampAddress, msg)
	txHash := common.HexToHash("0xaa")
	lg := buildExecutionStateChangedLog(t, poller.offRampAddress, msg, executor.FAILURE, nil, txHash, 321, 0)

	const head, maxSpan = uint64(500), uint64(50)
	mockCli.dynamicFunc = floodTestHead(head)
	mockCli.filterLogsFunc = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		from, to := q.FromBlock.Uint64(), q.ToBlock.Uint64()
		if to-from+1 > maxSpan {
			return nil, errors.New("query returned more than 10000 results")
		}
		if from <= 321 && 321 <= to {
			return []types.Log{lg}, nil
		}
		return nil, nil
	}
	mockCli.On("TransactionByHash", mock.Anything, txHash).Return(tx, nil)

	require.NoError(t, poller.pollForEvents(context.Background()))
	assert.Equal(t, head, poller.getLastPolledBlock())
	attempts, err := poller.GetExecutionAttempts(context.Background(), msg)
	require.NoError(t, err)
	assert.Len(t, attempts, 1)
}

// Completed sub-ranges keep the cursor; a block that cannot be scanned holds it.
func TestPollForEvents_CursorHeldAtUnscannableBlock(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	mockCli.dynamicFunc = floodTestHead(400)
	mockCli.filterLogsFunc = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		if q.ToBlock.Uint64() >= 300 {
			return nil, errors.New("too many logs")
		}
		return nil, nil
	}

	err := poller.pollForEvents(context.Background())
	require.Error(t, err)
	assert.Equal(t, uint64(299), poller.getLastPolledBlock(), "cursor must stop right before the failing block")

	// Once the RPC recovers, the next poll resumes from the held cursor.
	mockCli.filterLogsFunc = nil
	require.NoError(t, poller.pollForEvents(context.Background()))
	assert.Equal(t, uint64(400), poller.getLastPolledBlock())
}

// One block over the log cap is read from the block's direct OffRamp txs; multicall txs are skipped.
func TestPollForEvents_SingleBlockOverCapUsesBlockScan(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	msg := buildPollerTestMessage(t)
	direct := buildExecuteTxForMessage(t, poller.offRampAddress, msg)
	other := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	multicall := types.NewTx(&types.LegacyTx{To: &other, Gas: 1, Nonce: 7})

	const flooded = uint64(250)
	mockCli.dynamicFunc = floodTestHead(400)
	mockCli.filterLogsFunc = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		if q.FromBlock.Uint64() <= flooded && flooded <= q.ToBlock.Uint64() {
			return nil, errors.New("too many logs")
		}
		return nil, nil
	}
	mockCli.blockByNumberFunc = func(_ context.Context, n *big.Int) (*types.Block, error) {
		require.Equal(t, flooded, n.Uint64())
		return types.NewBlockWithHeader(&types.Header{Number: n}).
			WithBody(types.Body{Transactions: []*types.Transaction{multicall, direct}}), nil
	}
	lg := buildExecutionStateChangedLog(t, poller.offRampAddress, msg, executor.FAILURE, nil, direct.Hash(), flooded, 0)
	var receiptCalls []common.Hash
	mockCli.receiptFunc = func(_ context.Context, h common.Hash) (*types.Receipt, error) {
		receiptCalls = append(receiptCalls, h)
		return &types.Receipt{Logs: []*types.Log{&lg}}, nil
	}
	mockCli.On("TransactionByHash", mock.Anything, direct.Hash()).Return(direct, nil)

	require.NoError(t, poller.pollForEvents(context.Background()))
	assert.Equal(t, uint64(400), poller.getLastPolledBlock())
	assert.Equal(t, []common.Hash{direct.Hash()}, receiptCalls, "only the direct OffRamp tx needs a receipt")
	attempts, err := poller.GetExecutionAttempts(context.Background(), msg)
	require.NoError(t, err)
	assert.Len(t, attempts, 1)
}

// If the fallback also fails, the cursor is held and the block is never skipped.
func TestPollForEvents_BlockScanFailureHoldsCursor(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	mockCli.dynamicFunc = floodTestHead(100)
	mockCli.filterLogsFunc = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		if q.FromBlock.Uint64() <= 50 && 50 <= q.ToBlock.Uint64() {
			return nil, errors.New("too many logs")
		}
		return nil, nil
	}

	err := poller.pollForEvents(context.Background())
	require.ErrorContains(t, err, "block 50")
	assert.Equal(t, uint64(49), poller.getLastPolledBlock())
}

// Thousands of logs from one rejected multicall tx cost a single RPC, including across retries.
func TestPollForEvents_FloodFromOneTxFetchedOnce(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	other := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	multicall := types.NewTx(&types.LegacyTx{To: &other, Gas: 1})
	txHash := common.HexToHash("0xf100d")

	logs := make([]types.Log, 0, 10_000)
	for i := range 10_000 {
		msg := buildPollerTestMessageWithSeq(t, protocol.SequenceNumber(i+1))
		logs = append(logs, buildExecutionStateChangedLog(t, poller.offRampAddress, msg, executor.FAILURE, nil, txHash, 10, uint(i)))
	}
	mockCli.dynamicFunc = floodTestHead(20)
	mockCli.filterLogsFunc = func(context.Context, ethereum.FilterQuery) ([]types.Log, error) { return logs, nil }
	mockCli.On("TransactionByHash", mock.Anything, txHash).Return(multicall, nil)

	require.NoError(t, poller.pollForEvents(context.Background()))
	poller.setLastPolledBlock(0)
	require.NoError(t, poller.pollForEvents(context.Background()))
	mockCli.AssertNumberOfCalls(t, "TransactionByHash", 1)
}

// Distinct rejected txs cost exactly one fetch each, and none when the same range is polled again.
func TestPollForEvents_DistinctRejectedTxsFetchedOncePerTx(t *testing.T) {
	const txCount = 2_000
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	other := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	multicall := types.NewTx(&types.LegacyTx{To: &other, Gas: 1})

	logs := make([]types.Log, 0, txCount)
	for i := range txCount {
		msg := buildPollerTestMessageWithSeq(t, protocol.SequenceNumber(i+1))
		txHash := common.BigToHash(big.NewInt(int64(i + 1)))
		logs = append(logs, buildExecutionStateChangedLog(t, poller.offRampAddress, msg, executor.FAILURE, nil, txHash, 10, 0))
	}
	mockCli.dynamicFunc = floodTestHead(20)
	mockCli.filterLogsFunc = func(context.Context, ethereum.FilterQuery) ([]types.Log, error) { return logs, nil }
	mockCli.On("TransactionByHash", mock.Anything, mock.Anything).Return(multicall, nil)

	require.NoError(t, poller.pollForEvents(context.Background()))
	mockCli.AssertNumberOfCalls(t, "TransactionByHash", txCount)

	poller.setLastPolledBlock(0)
	require.NoError(t, poller.pollForEvents(context.Background()))
	mockCli.AssertNumberOfCalls(t, "TransactionByHash", txCount)
}

// A transient RPC error on TransactionByHash is not memoized, so the tx is retried next time.
func TestResolveTx_DoesNotCacheTransientErrors(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	msg := buildPollerTestMessage(t)
	tx := buildExecuteTxForMessage(t, poller.offRampAddress, msg)
	h := common.HexToHash("0x1")
	mockCli.On("TransactionByHash", mock.Anything, h).Return(nil, errors.New("rpc down")).Once()
	mockCli.On("TransactionByHash", mock.Anything, h).Return(tx, nil).Once()

	_, err := poller.resolveTx(context.Background(), h)
	require.Error(t, err)
	_, err = poller.resolveTx(context.Background(), h)
	require.NoError(t, err)
}

// Ready reflects progress, not full-poll success: an advancing poller is fresh, a stuck one goes stale.
func TestReady_TracksProgressNotFullPollSuccess(t *testing.T) {
	mockCli := new(mockClient)
	poller := setupTestPoller(t, mockCli, time.Hour)
	require.NoError(t, poller.StartOnce(evmExecutionAttemptPollerServiceName, func() error { return nil }))
	poller.backfillComplete.Store(true)
	poller.pollingMode.Store(true)
	mockCli.dynamicFunc = floodTestHead(400)
	mockCli.filterLogsFunc = func(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		if q.ToBlock.Uint64() >= 300 {
			return nil, errors.New("too many logs")
		}
		return nil, nil
	}

	stale := time.Now().Add(-time.Hour).Unix()
	poller.lastSuccessfulPoll.Store(stale)
	require.Error(t, poller.Ready(), "precondition: stale poller is not ready")

	require.Error(t, poller.pollForEvents(context.Background()), "poll still fails at block 300")
	assert.NoError(t, poller.Ready(), "cursor advanced to 299, so the poller is making progress")

	poller.lastSuccessfulPoll.Store(stale)
	require.Error(t, poller.pollForEvents(context.Background()), "no further progress possible")
	assert.Error(t, poller.Ready(), "a poller that is stuck must still go stale")
}
