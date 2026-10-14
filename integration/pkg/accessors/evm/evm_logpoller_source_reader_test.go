package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

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
	newReader := func(t *testing.T, processed int64) (*LogPollerSourceReader, *lpmocks.LogPoller) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: processed}, nil).Once()
		core := sourceReaderCore{lggr: logger.Test(t), onRampAddress: onRamp, ccipMessageSentTopic: topic.Hex()}
		return readyLogPollerReader(core, lp), lp
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

	t.Run("explicit range within the log poller block is read as given", func(t *testing.T) {
		r, lp := newReader(t, 120)
		lp.EXPECT().LogsWithSigs(mock.Anything, int64(90), int64(100), []common.Hash{topic}, onRamp).
			Return(nil, nil).Once()
		_, err := r.FetchMessageSentEvents(t.Context(), 90, 100)
		require.NoError(t, err)
	})

	t.Run("explicit range past the log poller block is an error", func(t *testing.T) {
		r, _ := newReader(t, 95)
		events, err := r.FetchMessageSentEvents(t.Context(), 90, 100)
		require.ErrorIs(t, err, ErrLogPollerBehind)
		require.Empty(t, events)
	})

	t.Run("inverted range is an error without querying the log poller", func(t *testing.T) {
		core := sourceReaderCore{lggr: logger.Test(t), onRampAddress: onRamp, ccipMessageSentTopic: topic.Hex()}
		r := readyLogPollerReader(core, lpmocks.NewLogPoller(t)) // no expectations: any log poller call fails the test
		_, err := r.FetchMessageSentEvents(t.Context(), 100, 90)
		require.ErrorContains(t, err, "invalid block range")
		require.NotErrorIs(t, err, ErrLogPollerBehind)
	})

	t.Run("reads fail until the log poller is ready", func(t *testing.T) {
		r := &LogPollerSourceReader{sourceReaderCore: sourceReaderCore{lggr: logger.Test(t)}, lp: lpmocks.NewLogPoller(t), cfg: &LogPollerConfig{}}
		_, err := r.FetchMessageSentEvents(t.Context(), 90, 0)
		require.ErrorIs(t, err, ErrLogPollerNotReady)
		require.ErrorIs(t, err, chainaccess.ErrSourceNotReady, "the Service matches the chain-agnostic sentinel")
	})
}

// stubHeadTracker serves fixed heads; any other Tracker call panics on the nil embedded interface.
type stubHeadTracker struct {
	heads.Tracker
	latest, finalized int64
}

func (s stubHeadTracker) LatestAndFinalizedBlock(context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return &evmtypes.Head{Number: s.latest}, &evmtypes.Head{Number: s.finalized}, nil
}

// The verifier must never advance past blocks the log poller has not indexed, so its block headers are the
// log poller's own blocks, read without the head tracker or RPC.
func TestBlockHeadersComeFromLogPoller(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	block := func(n int64) logpoller.Block {
		return logpoller.Block{BlockNumber: n, BlockHash: common.BigToHash(big.NewInt(n)), BlockTimestamp: ts}
	}
	header := func(n int64) *protocol.BlockHeader {
		return &protocol.BlockHeader{Number: uint64(n), Hash: protocol.Bytes32(common.BigToHash(big.NewInt(n))), Timestamp: ts} // #nosec G115 -- test block numbers are small
	}
	newReader := func(t *testing.T) (*LogPollerSourceReader, *lpmocks.LogPoller) {
		lp := lpmocks.NewLogPoller(t)
		latest := block(100)
		latest.FinalizedBlockNumber, latest.SafeBlockNumber = 80, 90
		lp.EXPECT().LatestBlock(mock.Anything).Return(latest, nil)
		// No head tracker or chain client: reading either panics.
		return &LogPollerSourceReader{sourceReaderCore: sourceReaderCore{lggr: logger.Test(t)}, lp: lp}, lp
	}

	t.Run("latest, finalized and safe are the log poller's blocks", func(t *testing.T) {
		r, lp := newReader(t)
		lp.EXPECT().GetBlocksRange(mock.Anything, []uint64{80}).Return([]logpoller.Block{block(80)}, nil).Once()
		lp.EXPECT().GetBlocksRange(mock.Anything, []uint64{90}).Return([]logpoller.Block{block(90)}, nil).Once()

		latest, finalized, err := r.LatestAndFinalizedBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, header(100), latest)
		require.Equal(t, header(80), finalized)

		safe, err := r.LatestSafeBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, header(90), safe)
	})

	t.Run("a block other than the one requested is an error", func(t *testing.T) {
		r, lp := newReader(t)
		lp.EXPECT().GetBlocksRange(mock.Anything, []uint64{80}).Return([]logpoller.Block{block(79)}, nil).Once()

		_, _, err := r.LatestAndFinalizedBlock(t.Context())
		require.ErrorContains(t, err, "log poller block 80 not found")
	})
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
			require.Equal(t, tc.want, NewLogPollerFinality(lp).FinalityViolated())
		})
	}
}

func TestNewLogPollerFinality_NilWithoutLogPoller(t *testing.T) {
	require.Nil(t, NewLogPollerFinality(nil))
	require.Nil(t, NewLogPollerFinality(logpoller.LogPollerDisabled))
}

// readyLogPollerReader is a reader whose log poller already finished loading.
func readyLogPollerReader(core sourceReaderCore, lp logpoller.LogPoller) *LogPollerSourceReader {
	r := &LogPollerSourceReader{sourceReaderCore: core, lp: lp, cfg: &LogPollerConfig{}}
	r.ready.Store(true)
	return r
}

// testSourceReaderParams are valid shared params for an onramp at 0x1234 emitting topic 0x01.
func testSourceReaderParams(t *testing.T, headTracker heads.Tracker) SourceReaderParams {
	return SourceReaderParams{
		ChainClient:          clienttest.NewClient(t),
		HeadTracker:          headTracker,
		OnRampAddress:        common.HexToAddress("0x1234"),
		CCIPMessageSentTopic: common.HexToHash("0x01").Hex(),
		ChainSelector:        protocol.ChainSelector(1337),
		Logger:               logger.Test(t),
		HeaderFetchBatchSize: 25,
	}
}

func TestNewLogPollerSourceReader_Validation(t *testing.T) {
	t.Run("disabled log poller is rejected", func(t *testing.T) {
		_, err := NewLogPollerSourceReader(t.Context(), testSourceReaderParams(t, heads.NullTracker),
			&LogPollerConfig{LogPoller: logpoller.LogPollerDisabled, VerifierID: "verifier-1"})
		require.ErrorContains(t, err, "log poller is not enabled")
	})

	t.Run("shared params are validated", func(t *testing.T) {
		params := testSourceReaderParams(t, heads.NullTracker)
		params.ChainClient = nil
		_, err := NewLogPollerSourceReader(t.Context(), params, &LogPollerConfig{
			LogPoller: lpmocks.NewLogPoller(t), VerifierID: "verifier-1",
		})
		require.ErrorContains(t, err, "chainClient is not set")
	})
}

func TestLogPollerStartup(t *testing.T) {
	onRamp := common.HexToAddress("0x1234")
	topic := common.HexToHash("0x01")
	name := "ccv-verifier - verifier-1:" + onRamp.Hex()
	// start builds a reader over a head tracker at latest 1000 and closes it on cleanup; it does not call LoadFrom.
	start := func(t *testing.T, lp *lpmocks.LogPoller) *LogPollerSourceReader {
		cfg := &LogPollerConfig{LogPoller: lp, VerifierID: "verifier-1", Retention: time.Hour}
		lp.EXPECT().UnregisterFilter(mock.Anything, name).Return(nil).Maybe()
		reader, err := NewLogPollerSourceReader(t.Context(), testSourceReaderParams(t, stubHeadTracker{latest: 1000, finalized: 900}), cfg)
		require.NoError(t, err)
		r := reader.(*LogPollerSourceReader)
		t.Cleanup(func() { require.NoError(t, r.Close()) })
		return r
	}
	expectRegister := func(lp *lpmocks.LogPoller) {
		lp.EXPECT().RegisterFilter(mock.Anything, mock.MatchedBy(func(f logpoller.Filter) bool {
			return f.Name == name && len(f.Addresses) == 1 && f.Addresses[0] == onRamp &&
				len(f.EventSigs) == 1 && f.EventSigs[0] == topic && f.Retention == time.Hour
		})).Return(nil).Once()
	}
	// expectStoredBlocks has the log poller keep blocks below the start block, so no anchor is needed.
	expectStoredBlocks := func(lp *lpmocks.LogPoller) {
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 400}, nil).Maybe()
	}
	expectDelete := func(lp *lpmocks.LogPoller, from int64, times int) {
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, from).Return(nil).Times(times)
		expectStoredBlocks(lp)
	}
	waitReady := func(t *testing.T, r *LogPollerSourceReader) {
		require.Eventually(t, r.ready.Load, 5*time.Second, 10*time.Millisecond)
	}

	t.Run("starts nothing before LoadFrom", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t)) // no expectations: any log poller call fails the test
		require.Never(t, r.ready.Load, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("LoadFrom after close starts nothing", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t)) // no expectations: any log poller call fails the test
		require.NoError(t, r.Close())
		r.LoadFrom(501)
		require.Never(t, r.ready.Load, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("registers the filter and deletes data from the start block before the replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		var order []string
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, logpoller.Filter) error { order = append(order, "register"); return nil }).Once()
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "delete"); return nil }).Once()
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "replay"); return nil }).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
		require.Equal(t, []string{"register", "delete", "replay"}, order)
	})

	// The delete can remove every stored block. An empty log poller would restart at the chain's
	// finalized block and skip the range if the replay failed, so it is anchored at the checkpoint first.
	t.Run("a log poller the delete emptied is anchored at the checkpoint before the replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		var order []string
		expectRegister(lp)
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "delete"); return nil }).Once()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows).Once()
		lp.EXPECT().SkipToBlock(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "anchor"); return nil }).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "replay"); return nil }).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
		require.Equal(t, []string{"delete", "anchor", "replay"}, order)
	})

	t.Run("an anchor failure is retried before any replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, int64(501)).Return(nil).Twice()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows).Twice()
		lp.EXPECT().SkipToBlock(mock.Anything, int64(501)).Return(errors.New("rpc down")).Once()
		lp.EXPECT().SkipToBlock(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("a failure to read the latest block is retried before any replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, int64(501)).Return(nil).Twice()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, errors.New("db down")).Once()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 400}, nil).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("a start block with no block before it is not anchored", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, int64(1)).Return(nil).Once()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows).Once()
		lp.EXPECT().Replay(mock.Anything, int64(1)).Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(1)
		waitReady(t, r)
	})

	t.Run("only the first start block counts", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		expectDelete(lp, 501, 1)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		r.LoadFrom(700)
		waitReady(t, r)
	})

	t.Run("a start block not mined yet needs no replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		expectDelete(lp, 1001, 1)
		r := start(t, lp)
		r.LoadFrom(1001)
		waitReady(t, r)
	})

	t.Run("registration failure is retried instead of failing construction", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errors.New("rpc down")).Once()
		expectRegister(lp)
		expectDelete(lp, 501, 1)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("delete failure is retried before any replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, int64(501)).Return(errors.New("db down")).Once()
		expectDelete(lp, 501, 1)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("finality violation during the replay is retried", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		expectDelete(lp, 501, 2)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(commontypes.ErrFinalityViolated).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("close stops a startup that keeps failing", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errors.New("rpc down")).Maybe()
		r := start(t, lp)
		r.LoadFrom(501)
		require.NoError(t, r.Close())
		require.False(t, r.ready.Load())
	})
}

func TestClose_UnregistersOwnFilter(t *testing.T) {
	newReader := func(t *testing.T, lp *lpmocks.LogPoller) *LogPollerSourceReader {
		return &LogPollerSourceReader{
			sourceReaderCore: sourceReaderCore{lggr: logger.Test(t)}, lp: lp,
			filterName: "ccv-verifier - verifier-1:0x1234", stopCh: make(services.StopChan),
		}
	}

	t.Run("unregisters the filter once", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().UnregisterFilter(mock.Anything, "ccv-verifier - verifier-1:0x1234").Return(nil).Once()
		r := newReader(t, lp)
		require.NoError(t, r.Close())
		require.NoError(t, r.Close(), "close is idempotent")
	})

	t.Run("unregister failure does not fail close", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().UnregisterFilter(mock.Anything, mock.Anything).Return(errors.New("db down")).Once()
		require.NoError(t, newReader(t, lp).Close())
	})
}
