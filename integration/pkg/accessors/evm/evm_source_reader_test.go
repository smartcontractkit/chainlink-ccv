package evm

import (
	"context"
	"errors"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

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

func blockNumFromArg(arg interface{}) int64 {
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

func newTestSourceReader(t *testing.T, cc evmclient.Client) *SourceReader {
	t.Helper()
	return &SourceReader{
		chainClient: cc,
		lggr:        logger.Test(t),
	}
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

	// Chunked into defaultMaxBatchSize (100) -> 100,100,50.
	require.Equal(t, []int{100, 100, 50}, c.batchSizes)

	// Every requested block number maps to a header with the right hash/fields.
	for i := 0; i < 250; i++ {
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
	require.Equal(t, []int{100, 10}, c.batchSizes)
}
