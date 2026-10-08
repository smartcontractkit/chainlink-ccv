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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_remote"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
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

// mockFilterLogsClient embeds evmclient.Client and overrides FilterLogs, so a test can serve logs
// without a chain. Any other RPC the reader reaches for panics on the nil embedded client, which
// is what pins "this path makes exactly one call".
type mockFilterLogsClient struct {
	evmclient.Client
	filterLogsFunc func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
}

func (m *mockFilterLogsClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return m.filterLogsFunc(ctx, q)
}

func TestFetchMessageSentEvents_SourceMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		feeToken  common.Address
		timestamp uint64
	}{
		{name: "timestamp supplied", feeToken: common.HexToAddress("0xabcd"), timestamp: 1700000000},
		{name: "timestamp unavailable", feeToken: common.HexToAddress("0xabcd")},
		{name: "zero fee asset address", timestamp: 1700000000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			onRampAddress := common.HexToAddress("0x1234")
			sender := common.HexToAddress("0x5678")
			receipts := []onramp.OnRampReceipt{
				{Issuer: common.HexToAddress("0x1111"), FeeTokenAmount: big.NewInt(2)},
				{Issuer: common.HexToAddress("0x2222"), FeeTokenAmount: big.NewInt(3)},
				{Issuer: common.HexToAddress("0x3333"), FeeTokenAmount: big.NewInt(4)},
			}
			ccvHash, err := protocol.ComputeCCVAndExecutorHash(
				[]protocol.UnknownAddress{receipts[0].Issuer.Bytes()}, receipts[1].Issuer.Bytes())
			require.NoError(t, err)
			message, err := protocol.NewMessage(
				1337, 100, 1,
				expectedSourceAddressBytes(onRampAddress), protocol.UnknownAddress{0x01},
				protocol.FinalityWaitForFinality, 300000, 200000, ccvHash,
				expectedSourceAddressBytes(sender), protocol.UnknownAddress{0x02}, nil, nil, nil,
			)
			require.NoError(t, err)
			encodedMessage, err := message.Encode()
			require.NoError(t, err)
			messageID, err := message.MessageID()
			require.NoError(t, err)
			onRampABI, err := onramp.OnRampMetaData.GetAbi()
			require.NoError(t, err)
			data, err := onRampABI.Events["CCIPMessageSent"].Inputs.NonIndexed().Pack(
				tc.feeToken, big.NewInt(0), encodedMessage, receipts, [][]byte{{0x01}},
			)
			require.NoError(t, err)
			log := types.Log{
				Address: onRampAddress,
				Topics: []common.Hash{
					onRampABI.Events["CCIPMessageSent"].ID,
					common.BigToHash(big.NewInt(100)),
					common.BytesToHash(sender.Bytes()),
					common.Hash(messageID),
				},
				Data:           data,
				BlockNumber:    95,
				BlockTimestamp: tc.timestamp,
				TxHash:         common.HexToHash("0xdeadbeef"),
				BlockHash:      common.HexToHash("0xb10c"),
			}
			// Both read paths must decode the same log into the same event.
			for _, viaLogPoller := range []bool{false, true} {
				t.Run(map[bool]string{false: "rpc", true: "log poller"}[viaLogPoller], func(t *testing.T) {
					// Configured inline rather than through newTestSourceReader: the reader has to agree
					// with the log this test builds on the onramp address and the source selector.
					reader := &SourceReader{
						lggr:                 logger.Test(t),
						onRampAddress:        onRampAddress,
						chainSelector:        protocol.ChainSelector(1337),
						onRampABI:            onRampABI,
						ccipMessageSentTopic: onRampABI.Events["CCIPMessageSent"].ID.Hex(),
					}
					if viaLogPoller {
						lp := lpmocks.NewLogPoller(t)
						lp.EXPECT().LogsWithSigs(mock.Anything, int64(90), int64(100),
							[]common.Hash{onRampABI.Events["CCIPMessageSent"].ID}, onRampAddress).
							Return([]logpoller.Log{toLogPollerLog(log)}, nil).Once()
						reader.lp = lp
						reader.lpCfg = readyLogPollerConfig()
					} else {
						// Only FilterLogs is implemented: an added block or transaction RPC fails the test.
						calls := 0
						t.Cleanup(func() { require.Equal(t, 1, calls) })
						reader.chainClient = &mockFilterLogsClient{
							filterLogsFunc: func(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
								calls++
								return []types.Log{log}, nil
							},
						}
					}
					reader.SetCriticalSourceInvariantCallback(func(context.Context) { t.Error("unexpected invalid event") })
					events, err := reader.FetchMessageSentEvents(t.Context(), 90, 100)
					require.NoError(t, err)
					require.Len(t, events, 1)
					require.Equal(t, protocol.UnknownAddress(tc.feeToken.Bytes()), events[0].FeeToken)
					require.Equal(t, messageID, events[0].MessageID)
					require.Equal(t, protocol.ByteSlice(common.HexToHash("0xb10c").Bytes()), events[0].BlockHash)
					require.Equal(t, *message, events[0].Message)
					// The reader surfaces the raw event. Normalizing it into the published policy view
					// happens in verifier/pkg/policy and is covered there.
					for i, receipt := range receipts {
						require.Equal(t, receipt.FeeTokenAmount, events[0].Receipts[i].FeeTokenAmount)
					}
					if tc.timestamp == 0 {
						require.True(t, events[0].BlockTimestamp.IsZero())
					} else {
						require.Equal(t, time.Unix(1700000000, 0).UTC(), events[0].BlockTimestamp)
					}
				})
			}
		})
	}
}

// toLogPollerLog is l as the log poller stores it, the form LogsWithSigs returns.
func toLogPollerLog(l types.Log) logpoller.Log {
	out := logpoller.Log{
		Address:     l.Address,
		BlockNumber: int64(l.BlockNumber), // #nosec G115 -- test block numbers are small
		BlockHash:   l.BlockHash,
		TxHash:      l.TxHash,
		Data:        l.Data,
		EventSig:    l.Topics[0],
	}
	for _, topic := range l.Topics {
		out.Topics = append(out.Topics, topic.Bytes())
	}
	if l.BlockTimestamp != 0 {
		out.BlockTimestamp = time.Unix(int64(l.BlockTimestamp), 0) // #nosec G115 -- test timestamps are small
	}
	return out
}

func TestFetchMessageSentEvents_LogPollerRange(t *testing.T) {
	topic := common.HexToHash("0x01")
	onRamp := common.HexToAddress("0x1234")
	newReader := func(t *testing.T, processed int64) (*SourceReader, *lpmocks.LogPoller) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: processed}, nil).Once()
		return &SourceReader{lggr: logger.Test(t), lp: lp, lpCfg: readyLogPollerConfig(), onRampAddress: onRamp, ccipMessageSentTopic: topic.Hex()}, lp
	}

	t.Run("open range ends at the log poller block", func(t *testing.T) {
		r, lp := newReader(t, 120)
		lp.EXPECT().LogsWithSigs(mock.Anything, int64(90), int64(120), []common.Hash{topic}, onRamp).
			Return(nil, nil).Once()
		_, err := r.FetchMessageSentEvents(t.Context(), 90, 0)
		require.NoError(t, err)
	})

	t.Run("range the log poller has not reached is an error", func(t *testing.T) {
		r, _ := newReader(t, 80)
		events, err := r.FetchMessageSentEvents(t.Context(), 90, 0)
		require.ErrorIs(t, err, ErrLogPollerBehind)
		require.Empty(t, events)
	})

	t.Run("reads fail until the log poller is ready", func(t *testing.T) {
		r := &SourceReader{lggr: logger.Test(t), lp: lpmocks.NewLogPoller(t), lpCfg: &LogPollerConfig{Ready: new(atomic.Bool)}}
		_, err := r.FetchMessageSentEvents(t.Context(), 90, 0)
		require.ErrorIs(t, err, ErrLogPollerNotReady)
		require.ErrorIs(t, err, chainaccess.ErrSourceNotReady, "the Service matches the chain-agnostic sentinel")
	})
}

// stubHeadTracker serves fixed heads; any other Tracker call panics on the nil embedded interface.
type stubHeadTracker struct {
	heads.Tracker
	latest, finalized, safe int64
}

func (s stubHeadTracker) LatestAndFinalizedBlock(context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return &evmtypes.Head{Number: s.latest}, &evmtypes.Head{Number: s.finalized}, nil
}

func (s stubHeadTracker) LatestSafeBlock(context.Context) (*evmtypes.Head, error) {
	return &evmtypes.Head{Number: s.safe}, nil
}

// The verifier must never advance past blocks whose logs the log poller has not indexed yet.
func TestBlocksAreCappedAtLogPollerBlock(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		processed               int64
		latest, finalized, safe uint64
	}{
		{name: "log poller caught up", processed: 150, latest: 100, finalized: 80, safe: 90},
		{name: "log poller between finalized and latest", processed: 85, latest: 85, finalized: 80, safe: 85},
		{name: "log poller below finalized", processed: 50, latest: 50, finalized: 50, safe: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lp := lpmocks.NewLogPoller(t)
			lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: tc.processed}, nil)
			// A capped block is re-read by number; when nothing is capped no header RPC is allowed.
			var cc evmclient.Client = clienttest.NewClient(t)
			if tc.processed < 100 {
				cc = newBatchFillingClient(t, "")
			}
			r := newTestSourceReader(t, cc)
			r.headTracker = stubHeadTracker{latest: 100, finalized: 80, safe: 90}
			r.lp = lp

			latest, finalized, err := r.LatestAndFinalizedBlock(t.Context())
			require.NoError(t, err)
			require.Equal(t, tc.latest, latest.Number)
			require.Equal(t, tc.finalized, finalized.Number)

			safe, err := r.LatestSafeBlock(t.Context())
			require.NoError(t, err)
			require.Equal(t, tc.safe, safe.Number)
		})
	}
}

func TestGetBlocksHeaders_BatchesAndChunks(t *testing.T) {
	t.Parallel()

	c := newBatchFillingClient(t, "")
	r := newTestSourceReader(t, c)

	blockNumbers := make([]uint64, 250)
	for i := range blockNumbers {
		blockNumbers[i] = uint64(i)
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

	blockNumbers := []uint64{1, 2, 3}
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

	blockNumbers := make([]uint64, 110)
	for i := range blockNumbers {
		blockNumbers[i] = uint64(i)
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

func TestLogPollerEnabled(t *testing.T) {
	for name, tc := range map[string]struct {
		lp   logpoller.LogPoller
		want bool
	}{
		"nil":      {lp: nil, want: false},
		"disabled": {lp: logpoller.LogPollerDisabled, want: false},
		"enabled":  {lp: lpmocks.NewLogPoller(t), want: true},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, LogPollerEnabled(tc.lp))
		})
	}
}

func TestFinalityViolated(t *testing.T) {
	for name, tc := range map[string]struct {
		healthy error
		want    bool
	}{
		"finality violated":      {healthy: commontypes.ErrFinalityViolated, want: true},
		"other unhealthy reason": {healthy: errors.New("rpc servers reported missing blocks"), want: false},
	} {
		t.Run(name, func(t *testing.T) {
			lp := lpmocks.NewLogPoller(t)
			lp.EXPECT().Healthy().Return(tc.healthy).Once()
			require.Equal(t, tc.want, (&SourceReader{lp: lp}).FinalityViolated())
		})
	}
}

func TestMessageSentFilterName(t *testing.T) {
	onRamp := common.HexToAddress("0x00000000000000000000000000000000000000aB")
	require.Equal(t, "ccv-verifier - verifier-1:"+onRamp.Hex(), MessageSentFilterName("verifier-1", onRamp))
}

// readyLogPollerConfig is a config whose log poller already finished loading.
func readyLogPollerConfig() *LogPollerConfig {
	ready := new(atomic.Bool)
	ready.Store(true)
	return &LogPollerConfig{Ready: ready}
}

func TestNewEVMSourceReader_LogPollerConfig(t *testing.T) {
	newReader := func(t *testing.T, cfg *LogPollerConfig) (chainaccess.SourceReader, error) {
		return NewEVMSourceReader(t.Context(), clienttest.NewClient(t), heads.NullTracker, common.HexToAddress("0x1234"),
			common.Address{}, common.HexToHash("0x01").Hex(), protocol.ChainSelector(1337), logger.Test(t), 25, nil, cfg)
	}

	t.Run("disabled log poller reads over rpc", func(t *testing.T) {
		reader, err := newReader(t, &LogPollerConfig{LogPoller: logpoller.LogPollerDisabled, VerifierID: "verifier-1"})
		require.NoError(t, err)
		r := reader.(*SourceReader)
		require.Nil(t, r.lp)
		r.LoadFrom(501) // no-op without a log poller
		require.NoError(t, r.Close())
	})

	t.Run("enabled log poller needs its startup hooks", func(t *testing.T) {
		_, err := newReader(t, &LogPollerConfig{LogPoller: lpmocks.NewLogPoller(t), VerifierID: "verifier-1"})
		require.ErrorContains(t, err, "log poller ready flag is not set")
		require.ErrorContains(t, err, "log poller filter lookup is not set")
	})
}

func TestLogPollerStartup(t *testing.T) {
	onRamp := common.HexToAddress("0x1234")
	topic := common.HexToHash("0x01")
	name := MessageSentFilterName("verifier-1", onRamp)
	// start builds a reader over a head tracker at latest 1000 and closes it on cleanup; it does not call LoadFrom.
	start := func(t *testing.T, lp *lpmocks.LogPoller, filterExisted bool) *SourceReader {
		cfg := &LogPollerConfig{
			LogPoller: lp, VerifierID: "verifier-1", Retention: time.Hour, Ready: new(atomic.Bool),
			FilterRegistered: func(context.Context, string) (bool, error) { return filterExisted, nil },
		}
		reader, err := NewEVMSourceReader(t.Context(), clienttest.NewClient(t), stubHeadTracker{latest: 1000, finalized: 900, safe: 950},
			onRamp, common.Address{}, topic.Hex(), protocol.ChainSelector(1337), logger.Test(t), 25, nil, cfg)
		require.NoError(t, err)
		r := reader.(*SourceReader)
		t.Cleanup(func() { require.NoError(t, r.Close()) })
		return r
	}
	expectRegister := func(lp *lpmocks.LogPoller) {
		lp.EXPECT().RegisterFilter(mock.Anything, mock.MatchedBy(func(f logpoller.Filter) bool {
			return f.Name == name && len(f.Addresses) == 1 && f.Addresses[0] == onRamp &&
				len(f.EventSigs) == 1 && f.EventSigs[0] == topic && f.Retention == time.Hour
		})).Return(nil).Once()
	}
	waitReady := func(t *testing.T, r *SourceReader) {
		require.Eventually(t, r.lpCfg.Ready.Load, 5*time.Second, 10*time.Millisecond)
	}

	t.Run("waits for the start block before touching the log poller", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t), false) // no expectations: any log poller call fails the test
		require.Never(t, r.lpCfg.Ready.Load, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("new filter is registered and replayed from the start block", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp, false)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("existing filter has data from the start block deleted before the replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		var order []string
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Once()
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "delete"); return nil }).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "replay"); return nil }).Once()
		r := start(t, lp, true)
		r.LoadFrom(501)
		waitReady(t, r)
		require.Equal(t, []string{"delete", "replay"}, order)
	})

	t.Run("only the first start block counts", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp, false)
		r.LoadFrom(501)
		r.LoadFrom(700)
		waitReady(t, r)
	})

	t.Run("a start block not mined yet needs no replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		r := start(t, lp, false)
		r.LoadFrom(1001)
		waitReady(t, r)
	})

	t.Run("registration failure is retried instead of failing construction", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errors.New("rpc down")).Once()
		expectRegister(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp, false)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("finality violation during the replay is reported and retried", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(commontypes.ErrFinalityViolated).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp, false)
		r.LoadFrom(501)
		require.Eventually(t, r.lpReplayViolated.Load, 5*time.Second, 10*time.Millisecond)
		require.True(t, r.FinalityViolated())
		waitReady(t, r)
	})

	t.Run("close stops a startup that keeps failing", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errors.New("rpc down")).Maybe()
		r := start(t, lp, false)
		r.LoadFrom(501)
		require.NoError(t, r.Close())
		require.False(t, r.lpCfg.Ready.Load())
	})
}
