package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

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
	latest, finalized, safe int64
}

func (s stubHeadTracker) LatestAndFinalizedBlock(context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return &evmtypes.Head{Number: s.latest}, &evmtypes.Head{Number: s.finalized}, nil
}

func (s stubHeadTracker) LatestSafeBlock(context.Context) (*evmtypes.Head, error) {
	return &evmtypes.Head{Number: s.safe}, nil
}

// advancingHeadTracker is a head tracker whose finalized block a test moves forward while the reader runs.
type advancingHeadTracker struct {
	heads.Tracker
	latest, finalized atomic.Int64
}

func newAdvancingHeadTracker(latest, finalized int64) *advancingHeadTracker {
	h := &advancingHeadTracker{}
	h.latest.Store(latest)
	h.finalized.Store(finalized)
	return h
}

func (h *advancingHeadTracker) LatestAndFinalizedBlock(context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return &evmtypes.Head{Number: h.latest.Load()}, &evmtypes.Head{Number: h.finalized.Load()}, nil
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
		return readyLogPollerReader(sourceReaderCore{lggr: logger.Test(t)}, lp), lp
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

func TestHealthy(t *testing.T) {
	missing := errors.New("rpc servers reported missing blocks 3 times in a row")
	for name, tc := range map[string]struct {
		healthy error
		want    error
	}{
		"wrapped violation": {healthy: fmt.Errorf("poll: %w", commontypes.ErrFinalityViolated)},
		"missing blocks":    {healthy: missing, want: missing},
	} {
		t.Run(name, func(t *testing.T) {
			lp := lpmocks.NewLogPoller(t)
			lp.EXPECT().Healthy().Return(tc.healthy).Once()
			err := readyLogPollerReader(sourceReaderCore{}, lp).Healthy()
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
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
			require.Equal(t, tc.want, readyLogPollerReader(sourceReaderCore{}, lp).FinalityViolated())
		})
	}
}

// readyLogPollerReader is a reader whose log poller already finished loading.
func readyLogPollerReader(core sourceReaderCore, lp logpoller.LogPoller) *LogPollerSourceReader {
	r := &LogPollerSourceReader{sourceReaderCore: core, lp: lp, cfg: &LogPollerConfig{}}
	r.loadStarted.Store(true)
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
	// startWith builds a reader over ht with a short retry backoff and closes it on cleanup; it does not call LoadFrom.
	// hook is cfg.Start, as the standalone verifier sets it; nil for none.
	startWith := func(t *testing.T, lp *lpmocks.LogPoller, ht heads.Tracker, hook func(context.Context, func(error)) error) *LogPollerSourceReader {
		cfg := &LogPollerConfig{LogPoller: lp, VerifierID: "verifier-1", Retention: time.Hour, Start: hook}
		lp.EXPECT().UnregisterFilter(mock.Anything, name).Return(nil).Maybe()
		reader, err := NewLogPollerSourceReader(t.Context(), testSourceReaderParams(t, ht), cfg)
		require.NoError(t, err)
		r := reader.(*LogPollerSourceReader)
		r.initBackoff, r.maxInitBackoff = 5*time.Millisecond, 20*time.Millisecond
		t.Cleanup(func() { require.NoError(t, r.Close()) })
		return r
	}
	// start builds a reader over atHead: latest 1000, finalized 900.
	atHead := stubHeadTracker{latest: 1000, finalized: 900, safe: 950}
	start := func(t *testing.T, lp *lpmocks.LogPoller) *LogPollerSourceReader {
		return startWith(t, lp, atHead, nil)
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
	waitReady := func(t *testing.T, r *LogPollerSourceReader) {
		require.Eventually(t, r.ready.Load, 5*time.Second, 10*time.Millisecond)
	}

	t.Run("takes the lease and starts the log poller before registering", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		var order []string
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, logpoller.Filter) error { order = append(order, "register"); return nil }).Once()
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "replay"); return nil }).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := startWith(t, lp, atHead, func(context.Context, func(error)) error { order = append(order, "lease+start"); return nil })
		r.LoadFrom(501)
		waitReady(t, r)
		require.Equal(t, []string{"lease+start", "register", "replay"}, order)
	})

	t.Run("reports the held lease while waiting and touches nothing", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t) // only UnregisterFilter on close is expected
		r := startWith(t, lp, atHead, func(ctx context.Context, onHeld func(error)) error {
			onHeld(errors.New("EVM database lease held by another process"))
			<-ctx.Done()
			return ctx.Err()
		})
		r.LoadFrom(501)
		require.Eventually(t, func() bool {
			err := r.Loaded()
			return errors.Is(err, ErrLogPollerNotReady) &&
				strings.Contains(err.Error(), "lease held by another process")
		}, 5*time.Second, 10*time.Millisecond)
		require.NoError(t, r.Close(), "Close ends the wait")
	})

	t.Run("stops reporting the held lease once it is taken", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		registering, unblock := make(chan struct{}), make(chan struct{})
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, logpoller.Filter) error { close(registering); <-unblock; return nil }).Once()
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := startWith(t, lp, atHead, func(_ context.Context, onHeld func(error)) error {
			onHeld(errors.New("EVM database lease held by another process"))
			return nil
		})
		r.LoadFrom(501)
		<-registering
		err := r.Loaded()
		require.ErrorIs(t, err, ErrLogPollerNotReady)
		require.NotContains(t, err.Error(), "lease held")
		close(unblock)
		waitReady(t, r)
	})

	t.Run("starts nothing before LoadFrom", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t)) // no expectations: any log poller call fails the test
		require.Never(t, r.ready.Load, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("LoadFrom after close starts nothing", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t)) // no expectations: any log poller call fails the test
		require.NoError(t, r.Close())
		r.LoadFrom(501)
		require.Never(t, r.ready.Load, 100*time.Millisecond, 10*time.Millisecond)
		// A closed reader is past LoadFrom, so its block reads no longer fall back to the head tracker.
		_, _, err := r.LatestAndFinalizedBlock(t.Context())
		require.ErrorIs(t, err, ErrLogPollerNotReady)
	})

	t.Run("registers the filter and replays from the start block without deleting", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		var order []string
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, logpoller.Filter) error { order = append(order, "register"); return nil }).Once()
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "replay"); return nil }).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
		require.Equal(t, []string{"register", "replay"}, order)
	})

	// An empty log poller (fresh DB, or emptied by remove-blocks) would restart at the chain's finalized
	// block and skip the range if the replay failed, so it is anchored at the checkpoint first.
	t.Run("an empty log poller is anchored at the checkpoint before the replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		var order []string
		expectRegister(lp)
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows).Once()
		lp.EXPECT().SkipToBlock(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "anchor"); return nil }).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { order = append(order, "replay"); return nil }).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
		require.Equal(t, []string{"anchor", "replay"}, order)
	})

	t.Run("an anchor failure is retried before any replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows).Twice()
		lp.EXPECT().SkipToBlock(mock.Anything, int64(501)).Return(errors.New("rpc down")).Once()
		lp.EXPECT().SkipToBlock(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	t.Run("a failure to read the latest block is retried before any replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Twice()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, errors.New("db down")).Once()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 400}, nil).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	// Below block 2 there is no block before the start block to anchor on, so the replay covers the chain
	// from block 1; from block 2 on an empty log poller is anchored at the block before it.
	for _, tc := range []struct {
		startBlock     uint64
		anchor, replay int64
	}{
		{startBlock: 0, replay: 1},
		{startBlock: 1, replay: 1},
		{startBlock: 2, anchor: 2, replay: 2},
	} {
		t.Run(fmt.Sprintf("an empty log poller with start block %d", tc.startBlock), func(t *testing.T) {
			lp := lpmocks.NewLogPoller(t)
			expectRegister(lp)
			lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows).Once()
			if tc.anchor != 0 {
				lp.EXPECT().SkipToBlock(mock.Anything, tc.anchor).Return(nil).Once()
			}
			lp.EXPECT().Replay(mock.Anything, tc.replay).Return(nil).Once()
			lp.EXPECT().Healthy().Return(nil).Once()
			r := start(t, lp)
			r.LoadFrom(tc.startBlock)
			waitReady(t, r)
		})
	}

	t.Run("only the first start block counts", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		r.LoadFrom(700)
		waitReady(t, r)
	})

	// A checkpoint at the finalized head is the normal caught-up case, not a checkpoint above finality.
	t.Run("a start block one past the finalized head not mined yet needs no replay", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		expectStoredBlocks(lp)
		r := startWith(t, lp, stubHeadTracker{latest: 1000, finalized: 1000}, nil)
		r.LoadFrom(1001)
		waitReady(t, r)
		require.NoError(t, r.Loaded())
	})

	// Data already stored at or above the start block is kept: the replay reads it again.
	t.Run("a log poller ahead of the checkpoint keeps its data and is replayed from the start block", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t) // strict: a delete or an anchor fails the test
		expectRegister(lp)
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 800}, nil).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	// After a testnet reset the checkpoint can be above the chain's finalized block. Anchoring there would
	// fail, and the reader must not count as loaded while it cannot serve, so the load waits for finality.
	for name, stored := range map[string]bool{"an empty": false, "a non-empty": true} {
		t.Run(name+" log poller with a checkpoint above finality waits for finality to reach it", func(t *testing.T) {
			lp := lpmocks.NewLogPoller(t) // only registration is expected until finality reaches the checkpoint
			lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil)
			ht := newAdvancingHeadTracker(450, 400)
			r := startWith(t, lp, ht, nil)
			r.LoadFrom(501)

			var checkpointErr CheckpointAboveFinalizedError
			require.Eventually(t, func() bool { return errors.As(r.Loaded(), &checkpointErr) }, 5*time.Second, 5*time.Millisecond)
			require.Equal(t, CheckpointAboveFinalizedError{Checkpoint: 500, Finalized: 400}, checkpointErr)
			err := r.Loaded()
			require.ErrorIs(t, err, chainaccess.ErrSourceNotReady)
			require.False(t, r.ready.Load())

			if stored {
				lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 450}, nil).Once()
			} else {
				lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows).Once()
				lp.EXPECT().SkipToBlock(mock.Anything, int64(501)).Return(nil).Once()
			}
			lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
			lp.EXPECT().Healthy().Return(nil).Once()
			ht.latest.Store(700)
			ht.finalized.Store(600)
			waitReady(t, r)
			require.NoError(t, r.Loaded())
		})
	}

	t.Run("registration failure is retried instead of failing construction", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errors.New("rpc down")).Once()
		expectRegister(lp)
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		require.ErrorIs(t, r.Loaded(), chainaccess.ErrSourceNotReady)
		r.LoadFrom(501)
		waitReady(t, r)
		require.NoError(t, r.Loaded())
	})

	// Blocks left from before the flag was turned off end below the checkpoint. The replay starts at the
	// start block and the poll loop resumes from the log poller's own last block, so the off period is
	// fetched again: an accepted cost.
	t.Run("a log poller behind the checkpoint is replayed without an anchor", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		expectRegister(lp)
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 300}, nil).Once()
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
	})

	// A violation is not transient: retrying would replay again over unsafe data, so the reader
	// loads blocked and recovery can still run on it. Replay returns the violation only from its own
	// backfill, which the startup skips today; this guards the reader if that changes.
	t.Run("finality violation during the replay stops the load and leaves the reader loaded but blocked", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Once()
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(commontypes.ErrFinalityViolated).Once()
		lggr, logs := logger.TestObserved(t, zapcore.ErrorLevel)
		r := start(t, lp)
		r.lggr = lggr
		r.LoadFrom(501)
		waitReady(t, r)

		require.NoError(t, r.Loaded())
		require.True(t, r.finalityBlocked.Load())
		// Healthy is not mocked: a blocked reader reports the violation without asking the log poller.
		require.True(t, r.FinalityViolated())
		violationLogs := logs.FilterMessageSnippet("finality violation")
		require.Equal(t, 1, violationLogs.Len())
		ctxMap := violationLogs.All()[0].ContextMap()
		require.Equal(t, r.filterName, ctxMap["filter"])
		require.Contains(t, ctxMap, "chainSelector")
		// No log poller read is mocked: a blocked reader refuses reads without touching the log poller.
		_, err := r.FetchMessageSentEvents(t.Context(), 501, 0)
		require.ErrorIs(t, err, commontypes.ErrFinalityViolated)
		_, _, err = r.LatestAndFinalizedBlock(t.Context())
		require.ErrorIs(t, err, commontypes.ErrFinalityViolated)
		_, err = r.LatestSafeBlock(t.Context())
		require.ErrorIs(t, err, commontypes.ErrFinalityViolated)
		// The goroutine returned instead of looping, so Close does not wait on a retry.
		done := make(chan struct{})
		go func() { _ = r.Close(); close(done) }()
		require.Eventually(t, func() bool {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}, 5*time.Second, 10*time.Millisecond)
		// Only a reset-reader prepare clears the block, so the finished load left it set.
		require.True(t, r.finalityBlocked.Load())
	})

	// This is how a startup violation really arrives: Replay hands the unfinalized part to the poll loop,
	// which finds the violation, so Replay returns nil and only Healthy() reports it.
	t.Run("a violation the replay leaves only in Healthy blocks the reader", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Once()
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(commontypes.ErrFinalityViolated).Once()
		lggr, logs := logger.TestObserved(t, zapcore.ErrorLevel)
		r := start(t, lp)
		r.lggr = lggr
		r.LoadFrom(501)
		waitReady(t, r)

		require.NoError(t, r.Loaded())
		require.True(t, r.finalityBlocked.Load())
		require.Equal(t, 1, logs.FilterMessageSnippet("finality violation").Len())
		// Once on Healthy: the block, not a second log poller check, keeps reporting the violation.
		require.True(t, r.FinalityViolated())
		_, err := r.FetchMessageSentEvents(t.Context(), 501, 0)
		require.ErrorIs(t, err, commontypes.ErrFinalityViolated)
	})

	t.Run("other log poller health errors after the replay do not block", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Once()
		expectStoredBlocks(lp)
		lp.EXPECT().Replay(mock.Anything, int64(501)).Return(nil).Once()
		lp.EXPECT().Healthy().Return(errors.New("rpc servers reported missing blocks")).Once()
		r := start(t, lp)
		r.LoadFrom(501)
		waitReady(t, r)
		require.False(t, r.finalityBlocked.Load())
	})

	// A chain whose load keeps failing stays in the process, reports not ready and keeps retrying.
	t.Run("a replay that keeps failing leaves the reader not ready and retrying", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Maybe()
		expectStoredBlocks(lp)
		var replays atomic.Int32
		lp.EXPECT().Replay(mock.Anything, int64(501)).
			RunAndReturn(func(context.Context, int64) error { replays.Add(1); return errors.New("replay failed") }).Maybe()
		r := start(t, lp)
		r.LoadFrom(501)

		require.Eventually(t, func() bool { return replays.Load() >= 3 }, 5*time.Second, 5*time.Millisecond)
		require.ErrorIs(t, r.Loaded(), chainaccess.ErrSourceNotReady)
		require.False(t, r.ready.Load())
	})

	// Until the load finishes the log poller's blocks may be stale or missing, so no read is served from it.
	t.Run("every read fails until the load finishes", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t) // no read is expected: any LatestBlock or GetBlocksRange fails the test
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errors.New("rpc down")).Maybe()
		r := start(t, lp)
		r.LoadFrom(501)

		_, err := r.FetchMessageSentEvents(t.Context(), 501, 0)
		require.ErrorIs(t, err, ErrLogPollerNotReady)
		_, _, err = r.LatestAndFinalizedBlock(t.Context())
		require.ErrorIs(t, err, ErrLogPollerNotReady)
		require.ErrorIs(t, err, chainaccess.ErrSourceNotReady)
		_, err = r.LatestSafeBlock(t.Context())
		require.ErrorIs(t, err, ErrLogPollerNotReady)
	})

	// With no checkpoint the verifier derives its start block from LatestAndFinalizedBlock before calling
	// LoadFrom. Those reads come from the head tracker, so the start block does not depend on what the log
	// poller holds, and a fresh log poller cannot stall the start.
	t.Run("before LoadFrom block reads come from the head tracker whatever the log poller holds", func(t *testing.T) {
		r := start(t, lpmocks.NewLogPoller(t)) // no expectations: any log poller call fails the test
		latest, finalized, err := r.LatestAndFinalizedBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, uint64(1000), latest.Number)
		require.Equal(t, uint64(900), finalized.Number)
		safe, err := r.LatestSafeBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, uint64(950), safe.Number)
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
