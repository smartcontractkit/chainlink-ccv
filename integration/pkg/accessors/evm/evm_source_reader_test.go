package evm

import (
	"context"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// mockFilterLogsClient embeds client.Client and overrides FilterLogs to
// simulate RPC range-limit rejections and successes.
type mockFilterLogsClient struct {
	client.Client
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

func newTestSourceReader(t *testing.T, chainClient client.Client) *SourceReader {
	t.Helper()
	return newTestSourceReaderWithTracker(t, chainClient, heads.NullTracker)
}

func newTestSourceReaderWithTracker(t *testing.T, chainClient client.Client, tracker heads.Tracker) *SourceReader {
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
