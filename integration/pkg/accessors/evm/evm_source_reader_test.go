package evm

import (
	"context"
	"errors"
	"math/big"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"

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

// TestNewEVMSourceReader_NoEagerRPCAtConstruction guards the regression where the constructor
// eagerly read the OnRamp static config (a GetStaticConfig RPC) to derive the RMN Remote address.
// A rate-limited provider then aborted construction, which in turn stopped every chain in the
// coordinator. The RMN Remote is now derived lazily on first GetRMNCursedSubjects.
func TestNewEVMSourceReader_NoEagerRPCAtConstruction(t *testing.T) {
	t.Parallel()

	// A client whose RPC always fails: any eager read performed during construction would fail it.
	rateLimitErr := errors.New("RPC call failed: rate limited")
	client := clienttest.NewClient(t)
	client.On("CallContract", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, rateLimitErr)

	reader, err := NewEVMSourceReader(
		context.Background(),
		client,
		heads.NullTracker,
		common.HexToAddress("0x1234"),
		common.Address{}, // deprecated configured RMN Remote, unset
		common.Hash{}.Hex(),
		protocol.ChainSelector(1337),
		logger.Test(t),
		25,
		nil,
	)
	require.NoError(t, err, "construction must not fail even when the RPC is unavailable")
	require.NotNil(t, reader)

	sr := reader.(*SourceReader)
	require.False(t, sr.rmnRemoteCaller.Derived(),
		"the RMN Remote caller must not be derived during construction")

	// The authoritative RMN Remote address is read lazily at query time, surfacing a transient
	// RPC error here rather than at construction. The failure is not cached, so a later call
	// re-attempts (self-healing once the provider recovers).
	_, err = sr.GetRMNCursedSubjects(context.Background())
	require.ErrorContains(t, err, "failed to read OnRamp static config")
	require.False(t, sr.rmnRemoteCaller.Derived(), "a failed derivation must not be cached")

	_, err = sr.GetRMNCursedSubjects(context.Background())
	require.ErrorContains(t, err, "failed to read OnRamp static config")

	// Exactly two RPCs, both triggered at query time — zero at construction.
	client.AssertNumberOfCalls(t, "CallContract", 2)
}

// TestGetRMNCursedSubjects_RetriesDerivationAndCaches exercises the lazy RMN Remote derivation
// end to end. A transient RPC failure surfaces at query time and is not cached; a later call
// re-derives; once derivation succeeds the caller is cached, so subsequent curse reads go
// straight to the RMN Remote without re-reading the OnRamp static config.
func TestGetRMNCursedSubjects_RetriesDerivationAndCaches(t *testing.T) {
	t.Parallel()

	onRampAddr := common.HexToAddress("0x1234")
	rmnRemoteAddr := common.HexToAddress("0x5678")

	onRampABI, err := onramp.OnRampMetaData.GetAbi()
	require.NoError(t, err)
	staticConfigOut, err := onRampABI.Methods["getStaticConfig"].Outputs.Pack(onramp.OnRampStaticConfig{
		RmnRemote: rmnRemoteAddr,
	})
	require.NoError(t, err)

	rmnRemoteABI, err := rmn_remote.RMNRemoteMetaData.GetAbi()
	require.NoError(t, err)
	wantSubjects := [][16]byte{{1, 2, 3}}
	cursedSubjectsOut, err := rmnRemoteABI.Methods["getCursedSubjects"].Outputs.Pack(wantSubjects)
	require.NoError(t, err)

	// Dispatch the mocked RPC by callee. Testify matches expectations in registration order,
	// so the OnRamp static-config read fails with a rate limit on the first two attempts and
	// then succeeds; the RMN Remote curse read always succeeds. Calls to any other contract
	// have no matching expectation and fail the test.
	rateLimitErr := errors.New("RPC call failed: rate limited")
	isTo := func(want common.Address) func(ethereum.CallMsg) bool {
		return func(msg ethereum.CallMsg) bool { return msg.To != nil && *msg.To == want }
	}
	var staticConfigCalls atomic.Int32
	client := clienttest.NewClient(t)
	client.On("CallContract", mock.Anything, mock.MatchedBy(isTo(rmnRemoteAddr)), mock.Anything).
		Return(cursedSubjectsOut, nil)
	client.On("CallContract", mock.Anything, mock.MatchedBy(isTo(onRampAddr)), mock.Anything).
		Run(func(mock.Arguments) { staticConfigCalls.Add(1) }).
		Return(nil, rateLimitErr).Twice()
	client.On("CallContract", mock.Anything, mock.MatchedBy(isTo(onRampAddr)), mock.Anything).
		Run(func(mock.Arguments) { staticConfigCalls.Add(1) }).
		Return(staticConfigOut, nil).Once()

	reader, err := NewEVMSourceReader(
		context.Background(),
		client,
		heads.NullTracker,
		onRampAddr,
		common.Address{}, // deprecated configured RMN Remote, unset
		common.Hash{}.Hex(),
		protocol.ChainSelector(1337),
		logger.Test(t),
		25,
		nil,
	)
	require.NoError(t, err)
	sr := reader.(*SourceReader)

	// The first two reads surface the derivation failure, which is never cached.
	for range 2 {
		_, err := sr.GetRMNCursedSubjects(context.Background())
		require.ErrorContains(t, err, "failed to read OnRamp static config")
		require.False(t, sr.rmnRemoteCaller.Derived(), "a failed derivation must not be cached")
	}

	// The third read re-derives successfully and returns the on-chain cursed subjects.
	subjects, err := sr.GetRMNCursedSubjects(context.Background())
	require.NoError(t, err)
	want := []protocol.Bytes16{{1, 2, 3}}
	require.Equal(t, want, subjects)
	require.True(t, sr.rmnRemoteCaller.Derived())

	// With derivation cached, a further read goes straight to the RMN Remote: the static-config
	// call count does not grow.
	subjects, err = sr.GetRMNCursedSubjects(context.Background())
	require.NoError(t, err)
	require.Equal(t, want, subjects)
	require.Equal(t, int32(3), staticConfigCalls.Load())
}
