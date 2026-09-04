package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// mockFilterLogsClient embeds evmclient.Client and overrides FilterLogs to
// simulate RPC range-limit rejections and successes.
type mockFilterLogsClient struct {
	evmclient.Client
	filterLogsFunc func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
}

func (m *mockFilterLogsClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return m.filterLogsFunc(ctx, q)
}

// mockHeadTracker wraps heads.NullTracker and overrides LatestAndFinalizedBlock.
type mockHeadTracker struct {
	heads.Tracker
	latest    *evmtypes.Head
	finalized *evmtypes.Head
	err       error
}

func (m *mockHeadTracker) LatestAndFinalizedBlock(ctx context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return m.latest, m.finalized, m.err
}

func newTestSourceReader(t *testing.T, chainClient evmclient.Client) *SourceReader {
	t.Helper()
	return newTestSourceReaderWithTracker(t, chainClient, heads.NullTracker)
}

func newTestSourceReaderWithTracker(t *testing.T, chainClient evmclient.Client, tracker heads.Tracker) *SourceReader {
	t.Helper()
	return &SourceReader{
		chainClient:          chainClient,
		headTracker:          tracker,
		onRampAddress:        common.HexToAddress("0x1234"),
		ccipMessageSentTopic: common.Hash{}.Hex(),
		chainSelector:        protocol.ChainSelector(1337),
		lggr:                 logger.Test(t),
		maxFilterBlockRange:  new(atomic.Uint64),
	}
}

func rangeLimitError() error {
	return fmt.Errorf("RPC call failed: exceeded max range limit for eth_getLogs")
}

func TestFetchMessageSentEvents_BoundedQueryShrinksAndRetries(t *testing.T) {
	t.Parallel()

	var queriedRanges [][2]uint64 // track [from, to] pairs
	callCount := 0

	client := &mockFilterLogsClient{
		filterLogsFunc: func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
			from := q.FromBlock.Uint64()
			to := q.ToBlock.Uint64()
			queriedRanges = append(queriedRanges, [2]uint64{from, to})
			callCount++

			// Reject ranges > 500 blocks
			if to-from+1 > 500 {
				return nil, rangeLimitError()
			}
			return []types.Log{}, nil
		},
	}

	reader := newTestSourceReader(t, client)

	// Query [0, 999] — 1000 blocks, should be rejected, halved to 500, then succeed
	events, err := reader.FetchMessageSentEvents(context.Background(), big.NewInt(0), big.NewInt(999))
	require.NoError(t, err)
	require.Empty(t, events)

	// Should have made 3 calls: [0,999] rejected, [0,499] ok, [500,999] ok
	require.Len(t, queriedRanges, 3)
	require.Equal(t, [2]uint64{0, 999}, queriedRanges[0])
	require.Equal(t, [2]uint64{0, 499}, queriedRanges[1])
	require.Equal(t, [2]uint64{500, 999}, queriedRanges[2])

	// The shrunk limit should persist
	require.Equal(t, uint64(500), reader.maxFilterBlockRange.Load())
}

func TestFetchMessageSentEvents_ShrunkLimitPersistsForNextCall(t *testing.T) {
	t.Parallel()

	callCount := 0
	client := &mockFilterLogsClient{
		filterLogsFunc: func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
			callCount++
			from := q.FromBlock.Uint64()
			to := q.ToBlock.Uint64()
			if to-from+1 > 500 {
				return nil, rangeLimitError()
			}
			return []types.Log{}, nil
		},
	}

	reader := newTestSourceReader(t, client)

	// First call: [0, 999] — triggers shrink to 500
	_, err := reader.FetchMessageSentEvents(context.Background(), big.NewInt(0), big.NewInt(999))
	require.NoError(t, err)
	require.Equal(t, uint64(500), reader.maxFilterBlockRange.Load())

	// Second call: [1000, 1999] — should use the persisted 500 limit
	var secondCallRanges [][2]uint64
	client.filterLogsFunc = func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
		from := q.FromBlock.Uint64()
		to := q.ToBlock.Uint64()
		secondCallRanges = append(secondCallRanges, [2]uint64{from, to})
		return []types.Log{}, nil
	}

	_, err = reader.FetchMessageSentEvents(context.Background(), big.NewInt(1000), big.NewInt(1999))
	require.NoError(t, err)

	// Should have chunked into [1000,1499], [1500,1999]
	require.Len(t, secondCallRanges, 2)
	require.Equal(t, [2]uint64{1000, 1499}, secondCallRanges[0])
	require.Equal(t, [2]uint64{1500, 1999}, secondCallRanges[1])
}

func TestFetchMessageSentEvents_UnboundedQueryShrinksAndRetries(t *testing.T) {
	t.Parallel()

	latestHead := &evmtypes.Head{
		Number:    999,
		Hash:      common.BigToHash(big.NewInt(999)),
		Timestamp: time.Now(),
	}
	tracker := &mockHeadTracker{latest: latestHead}

	var queriedRanges [][2]uint64
	client := &mockFilterLogsClient{
		filterLogsFunc: func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
			from := q.FromBlock.Uint64()
			to := q.ToBlock.Uint64()
			queriedRanges = append(queriedRanges, [2]uint64{from, to})
			if to-from+1 > 500 {
				return nil, rangeLimitError()
			}
			return []types.Log{}, nil
		},
	}

	reader := newTestSourceReaderWithTracker(t, client, tracker)

	// Unbounded query [0, nil] — resolves latest=999, span=1000, halved to 500
	events, err := reader.FetchMessageSentEvents(context.Background(), big.NewInt(0), nil)
	require.NoError(t, err)
	require.Empty(t, events)

	// Should have made 3 calls: [0,999] rejected, [0,499] ok, [500,999] ok
	require.Len(t, queriedRanges, 3)
	require.Equal(t, [2]uint64{0, 999}, queriedRanges[0])
	require.Equal(t, [2]uint64{0, 499}, queriedRanges[1])
	require.Equal(t, [2]uint64{500, 999}, queriedRanges[2])

	require.Equal(t, uint64(500), reader.maxFilterBlockRange.Load())
}

func TestFetchMessageSentEvents_GenericErrorDoesNotShrink(t *testing.T) {
	t.Parallel()

	genericErr := fmt.Errorf("connection refused")
	client := &mockFilterLogsClient{
		filterLogsFunc: func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
			return nil, genericErr
		},
	}

	reader := newTestSourceReader(t, client)

	events, err := reader.FetchMessageSentEvents(context.Background(), big.NewInt(0), big.NewInt(999))
	require.ErrorIs(t, err, genericErr)
	require.Empty(t, events)

	// Limit should NOT be set
	require.Equal(t, uint64(0), reader.maxFilterBlockRange.Load())
}

type stubOnRampStaticConfigGetter struct {
	cfg onramp.OnRampStaticConfig
	err error
}

func (s stubOnRampStaticConfigGetter) GetStaticConfig(*bind.CallOpts) (onramp.OnRampStaticConfig, error) {
	return s.cfg, s.err
}

func TestDeriveRMNRemoteFromOnRamp(t *testing.T) {
	t.Parallel()

	rmnRemote := common.HexToAddress("0x0000000000000000000000000000000000005678")

	t.Run("returns the RMN remote from the static config", func(t *testing.T) {
		t.Parallel()

		got, err := deriveRMNRemoteFromOnRamp(context.Background(), stubOnRampStaticConfigGetter{
			cfg: onramp.OnRampStaticConfig{RmnRemote: rmnRemote},
		})
		require.NoError(t, err)
		require.Equal(t, rmnRemote, got)
	})

	t.Run("wraps read errors", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("rpc failed")
		_, err := deriveRMNRemoteFromOnRamp(context.Background(), stubOnRampStaticConfigGetter{err: wantErr})
		require.ErrorIs(t, err, wantErr)
		require.ErrorContains(t, err, "failed to read OnRamp static config")
	})

	t.Run("rejects a zero RMN remote", func(t *testing.T) {
		t.Parallel()

		_, err := deriveRMNRemoteFromOnRamp(context.Background(), stubOnRampStaticConfigGetter{})
		require.ErrorContains(t, err, "zero RMN Remote address")
	})
}

// batchFillingClient is a mock client.Client that answers eth_getBlockByNumber
// batch elements with a synthetic header, deriving the block number from the
// element's hex argument.
type batchFillingClient struct {
	*clienttest.Client
	batchSizes []int
}

func newBatchFillingClient(t *testing.T, failMethod string) *batchFillingClient {
	m := clienttest.NewClient(t)
	c := &batchFillingClient{Client: m}

	m.On("BatchCallContext", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			b := args.Get(1).([]rpc.BatchElem)
			c.batchSizes = append(c.batchSizes, len(b))
			for i := range b {
				n := blockNumFromArg(b[i].Args[0])
				if methodFails(failMethod, n) {
					b[i].Error = errors.New("boom")
					continue
				}
				head := &evmtypes.Head{
					Number:     n,
					Hash:       common.BigToHash(big.NewInt(n)),
					ParentHash: common.BigToHash(big.NewInt(n - 1)),
					Timestamp:  time.Unix(n, 0).UTC(),
				}
				*(b[i].Result.(**evmtypes.Head)) = head
			}
		}).
		Return(nil)

	return c
}

func methodFails(failMethod string, blockNum int64) bool {
	switch failMethod {
	case "head_fail_all":
		return true
	case "head_fail_50":
		return blockNum == 50
	default:
		return false
	}
}

func blockNumFromArg(arg any) int64 {
	hex, _ := arg.(string)
	if hex == "" || hex == "latest" {
		return 0
	}
	n, err := strconv.ParseInt(hex, 0, 64)
	if err != nil {
		return 0
	}
	return n
}

func TestGetBlocksHeaders_BatchesAndChunks(t *testing.T) {
	t.Parallel()

	c := newBatchFillingClient(t, "")
	r := newTestSourceReader(t, c)

	blockNumbers := make([]*big.Int, 250)
	for i := range blockNumbers {
		blockNumbers[i] = big.NewInt(int64(i))
	}

	headers, err := r.GetBlocksHeaders(context.Background(), blockNumbers)
	require.NoError(t, err)
	require.Len(t, headers, 250)

	// Chunked into defaultMaxBatchSize (25) -> 25,25,25,25,25,25,25,25,25,25.
	require.Equal(t, []int{25, 25, 25, 25, 25, 25, 25, 25, 25, 25}, c.batchSizes)

	// Every requested block number maps to a header with the right hash/fields.
	for i := range 250 {
		h, ok := headers[uint64(i)]
		require.True(t, ok, "missing header for block %d", i)
		require.Equal(t, uint64(i), h.Number)
		require.Equal(t, protocol.Bytes32(common.BigToHash(big.NewInt(int64(i)))), h.Hash)
		require.Equal(t, protocol.Bytes32(common.BigToHash(big.NewInt(int64(i-1)))), h.ParentHash)
	}

	// The whole batch path must never fall back to one-request-per-block.
	c.AssertNotCalled(t, "HeadByNumber", mock.Anything, mock.Anything)
}

func TestGetBlocksHeaders_SingleBatchWithinLimit(t *testing.T) {
	t.Parallel()

	c := newBatchFillingClient(t, "")
	r := newTestSourceReader(t, c)

	blockNumbers := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	headers, err := r.GetBlocksHeaders(context.Background(), blockNumbers)
	require.NoError(t, err)
	require.Len(t, headers, 3)
	require.Equal(t, []int{3}, c.batchSizes)
	require.Equal(t, uint64(2), headers[2].Number)
}

func TestGetBlocksHeaders_SkipsFailedBatchElements(t *testing.T) {
	t.Parallel()

	c := newBatchFillingClient(t, "head_fail_50")
	r := newTestSourceReader(t, c)

	blockNumbers := make([]*big.Int, 110)
	for i := range blockNumbers {
		blockNumbers[i] = big.NewInt(int64(i))
	}

	headers, err := r.GetBlocksHeaders(context.Background(), blockNumbers)
	require.NoError(t, err)
	require.Len(t, headers, 109) // block 50 errored and should be absent
	_, present := headers[50]
	require.False(t, present)
	require.Equal(t, []int{25, 25, 25, 25, 10}, c.batchSizes)
}
