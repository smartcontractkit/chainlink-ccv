package evm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	evmclient "github.com/smartcontractkit/chainlink-evm/pkg/client"
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
	latest, finalized, safe int64
}

func (s stubHeadTracker) LatestAndFinalizedBlock(context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return &evmtypes.Head{Number: s.latest}, &evmtypes.Head{Number: s.finalized}, nil
}

func (s stubHeadTracker) LatestSafeBlock(context.Context) (*evmtypes.Head, error) {
	return &evmtypes.Head{Number: s.safe}, nil
}

// The verifier must never advance past blocks whose logs the log poller has not indexed yet, and
// finalized must not rely on the log poller's processed block, which can still be on a forked chain.
func TestBlocksAreCappedAtLogPollerBlock(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		processed, lpFin, lpSafe int64
		latest, finalized, safe  uint64
	}{
		{name: "log poller caught up", processed: 150, lpFin: 80, lpSafe: 90, latest: 100, finalized: 80, safe: 90},
		{name: "log poller finalized behind head tracker", processed: 100, lpFin: 70, lpSafe: 85, latest: 100, finalized: 70, safe: 85},
		{name: "log poller far behind", processed: 50, lpFin: 40, lpSafe: 45, latest: 50, finalized: 40, safe: 45},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lp := lpmocks.NewLogPoller(t)
			lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{
				BlockNumber: tc.processed, FinalizedBlockNumber: tc.lpFin, SafeBlockNumber: tc.lpSafe,
			}, nil)
			// A capped block is re-read by number; when nothing is capped no header RPC is allowed.
			var cc evmclient.Client = clienttest.NewClient(t)
			if tc.processed < 100 || tc.lpFin < 80 || tc.lpSafe < 90 {
				cc = newBatchFillingClient(t, "")
			}
			core := newTestSourceReader(t, cc).sourceReaderCore
			core.headTracker = stubHeadTracker{latest: 100, finalized: 80, safe: 90}
			r := &LogPollerSourceReader{sourceReaderCore: core, lp: lp}

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

	t.Run("enabled log poller needs its filter lookup", func(t *testing.T) {
		_, err := NewLogPollerSourceReader(t.Context(), testSourceReaderParams(t, heads.NullTracker),
			&LogPollerConfig{LogPoller: lpmocks.NewLogPoller(t), VerifierID: "verifier-1"})
		require.ErrorContains(t, err, "log poller filter lookup is not set")
	})

	t.Run("shared params are validated", func(t *testing.T) {
		params := testSourceReaderParams(t, heads.NullTracker)
		params.ChainClient = nil
		_, err := NewLogPollerSourceReader(t.Context(), params, &LogPollerConfig{
			LogPoller: lpmocks.NewLogPoller(t), VerifierID: "verifier-1",
			FilterRegistered: func(context.Context, string) (bool, error) { return false, nil },
		})
		require.ErrorContains(t, err, "chainClient is not set")
	})
}

func TestLogPollerStartup(t *testing.T) {
	onRamp := common.HexToAddress("0x1234")
	topic := common.HexToHash("0x01")
	name := "ccv-verifier - verifier-1:" + onRamp.Hex()
	// start builds a reader over a head tracker at latest 1000 and closes it on cleanup; it does not call LoadFrom.
	start := func(t *testing.T, lp *lpmocks.LogPoller, filterExisted bool) *LogPollerSourceReader {
		cfg := &LogPollerConfig{
			LogPoller: lp, VerifierID: "verifier-1", Retention: time.Hour,
			FilterRegistered: func(context.Context, string) (bool, error) { return filterExisted, nil },
		}
		lp.EXPECT().UnregisterFilter(mock.Anything, name).Return(nil).Maybe()
		reader, err := NewLogPollerSourceReader(t.Context(), testSourceReaderParams(t, stubHeadTracker{latest: 1000, finalized: 900, safe: 950}), cfg)
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
	waitReady := func(t *testing.T, r *LogPollerSourceReader) {
		require.Eventually(t, r.ready.Load, 5*time.Second, 10*time.Millisecond)
	}

	t.Run("starts nothing before LoadFrom", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t), false) // no expectations: any log poller call fails the test
		require.Never(t, r.ready.Load, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("LoadFrom after close starts nothing", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t), false) // no expectations: any log poller call fails the test
		require.NoError(t, r.Close())
		r.LoadFrom(501)
		require.Never(t, r.ready.Load, 100*time.Millisecond, 10*time.Millisecond)
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

	t.Run("finality violation during the replay is retried", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(commontypes.ErrFinalityViolated).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		r := start(t, lp, false)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("close stops a startup that keeps failing", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errors.New("rpc down")).Maybe()
		r := start(t, lp, false)
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
