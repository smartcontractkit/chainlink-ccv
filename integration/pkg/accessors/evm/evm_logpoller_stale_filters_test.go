package evm

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/logpollerdb"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// staleFilterRecorder orders calls made on the ORM and on the log poller in one list.
type staleFilterRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *staleFilterRecorder) add(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *staleFilterRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// storedFiltersORM implements only the two calls the stale cleanup makes; any other method panics on the nil
// embedded interface.
type storedFiltersORM struct {
	logpoller.ORM
	rec       *staleFilterRecorder
	filters   map[string]logpoller.Filter
	loadErr   error
	deleteErr error
}

func (f *storedFiltersORM) LoadFilters(context.Context) (map[string]logpoller.Filter, error) {
	f.rec.add("load")
	return f.filters, f.loadErr
}

func (f *storedFiltersORM) DeleteFilter(_ context.Context, name string) error {
	f.rec.add("orm-delete " + name)
	return f.deleteErr
}

func TestLogPollerStaleFilterCleanup(t *testing.T) {
	onRamp := common.HexToAddress("0x1234")
	oldOnRamp := common.HexToAddress("0xabcd")
	own := verifierFilterName("verifier-1", onRamp)
	stale := verifierFilterName("verifier-1", oldOnRamp)

	type fixture struct {
		r   *LogPollerSourceReader
		rec *staleFilterRecorder
		orm *storedFiltersORM
	}
	// start builds a reader over a head tracker at latest 1000; the fake ORM holds the stored filters.
	start := func(t *testing.T, stored map[string]logpoller.Filter, unregisterErr error) fixture {
		rec := &staleFilterRecorder{}
		orm := &storedFiltersORM{rec: rec, filters: stored}
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, logpoller.Filter) error { rec.add("register"); return nil }).Maybe()
		lp.EXPECT().UnregisterFilter(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, name string) error {
				if name != own {
					rec.add("unregister " + name)
				}
				return unregisterErr
			}).Maybe()
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, int64) error { rec.add("delete-data"); return nil }).Maybe()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 400}, nil).Maybe()
		lp.EXPECT().Replay(mock.Anything, mock.Anything).Return(nil).Maybe()
		lp.EXPECT().Healthy().Return(nil).Maybe()

		cfg := &LogPollerConfig{LogPoller: lp, ORM: orm, VerifierID: "verifier-1", Retention: time.Hour}
		reader, err := NewLogPollerSourceReader(t.Context(), testSourceReaderParams(t, stubHeadTracker{latest: 1000, finalized: 900}), cfg)
		require.NoError(t, err)
		r := reader.(*LogPollerSourceReader)
		t.Cleanup(func() { require.NoError(t, r.Close()) })
		return fixture{r: r, rec: rec, orm: orm}
	}
	waitReady := func(t *testing.T, r *LogPollerSourceReader) {
		require.Eventually(t, r.ready.Load, 5*time.Second, 10*time.Millisecond)
	}

	t.Run("a stale filter is removed from the database, then from the log poller, before the data delete", func(t *testing.T) {
		f := start(t, map[string]logpoller.Filter{
			own:   {Name: own},
			stale: {Name: stale},
			// Another verifier's filter, including one whose ID extends ours, and other shapes stay.
			verifierFilterName("verifier-2", oldOnRamp):   {},
			verifierFilterName("verifier-1:x", oldOnRamp): {},
			"legacy filter": {},
			"ccv-verifier - verifier-1:not-an-address": {},
		}, nil)
		f.r.LoadFrom(501)
		waitReady(t, f.r)
		assert.Equal(t, []string{"register", "load", "orm-delete " + stale, "unregister " + stale, "delete-data"}, f.rec.snapshot())
	})

	t.Run("errors are warnings and the load still completes", func(t *testing.T) {
		f := start(t, map[string]logpoller.Filter{stale: {}}, errors.New("unregister failed"))
		f.orm.deleteErr = errors.New("delete failed")
		f.r.LoadFrom(501)
		waitReady(t, f.r)
		assert.Equal(t, []string{"register", "load", "orm-delete " + stale, "unregister " + stale, "delete-data"}, f.rec.snapshot())
	})

	t.Run("a failure to load the stored filters is a warning and does not retry the load", func(t *testing.T) {
		f := start(t, nil, nil)
		f.orm.loadErr = errors.New("db down")
		f.r.LoadFrom(501)
		waitReady(t, f.r)
		assert.Equal(t, []string{"register", "load", "delete-data"}, f.rec.snapshot())
	})

	t.Run("the cleanup runs when the replay is skipped because the checkpoint is at the head", func(t *testing.T) {
		f := start(t, map[string]logpoller.Filter{stale: {}}, nil)
		f.r.LoadFrom(1001)
		waitReady(t, f.r)
		assert.Contains(t, f.rec.snapshot(), "orm-delete "+stale)
		assert.Contains(t, f.rec.snapshot(), "unregister "+stale)
	})

	t.Run("without an ORM the cleanup is skipped", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t)
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil).Once()
		lp.EXPECT().UnregisterFilter(mock.Anything, own).Return(nil).Maybe()
		lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, mock.Anything).Return(nil).Once()
		lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 400}, nil).Maybe()
		lp.EXPECT().Replay(mock.Anything, mock.Anything).Return(nil).Once()
		lp.EXPECT().Healthy().Return(nil).Once()
		cfg := &LogPollerConfig{LogPoller: lp, VerifierID: "verifier-1", Retention: time.Hour}
		reader, err := NewLogPollerSourceReader(t.Context(), testSourceReaderParams(t, stubHeadTracker{latest: 1000, finalized: 900}), cfg)
		require.NoError(t, err)
		r := reader.(*LogPollerSourceReader)
		t.Cleanup(func() { require.NoError(t, r.Close()) })
		r.LoadFrom(501)
		waitReady(t, r)
	})
}

// A crash leaves the old on-ramp's filter registered. The restart with a changed on-ramp must leave
// exactly one filter for the verifier on its chain, and never touch another chain's.
func TestLogPollerStaleFilterCleanup_RealORM(t *testing.T) {
	testDB := testutil.NewTestDB(t)
	handle := logpollerdb.NewDB(testDB.DB)
	ctx := t.Context()

	const chainID, otherChainID = 910_101, 910_102
	newORM := func(id int64) *logpoller.DSORM { return logpoller.NewORM(big.NewInt(id), handle, logger.Test(t)) }
	orm, otherORM := newORM(chainID), newORM(otherChainID)

	onRamp := common.HexToAddress("0x1234")
	oldOnRamp := common.HexToAddress("0xabcd")
	register := func(o *logpoller.DSORM, id string, addr common.Address) {
		require.NoError(t, o.InsertFilter(ctx, logpoller.Filter{
			Name:      verifierFilterName(id, addr),
			Addresses: evmtypes.AddressArray{addr},
			EventSigs: evmtypes.HashArray{common.HexToHash("0x01")},
		}))
	}
	register(orm, "verifier-1", oldOnRamp)      // left behind by the crashed run
	register(orm, "verifier-2", oldOnRamp)      // another verifier on the same chain
	register(otherORM, "verifier-1", oldOnRamp) // the same verifier's filter on another chain

	lp := lpmocks.NewLogPoller(t)
	// The reader registers its own filter through the log poller; the ORM stands in for that here.
	lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, f logpoller.Filter) error { return orm.InsertFilter(ctx, f) }).Once()
	lp.EXPECT().UnregisterFilter(mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, name string) error { return orm.DeleteFilter(ctx, name) }).Maybe()
	lp.EXPECT().DeleteLogsAndBlocksAfter(mock.Anything, mock.Anything).Return(nil).Once()
	lp.EXPECT().LatestBlock(mock.Anything).Return(logpoller.Block{BlockNumber: 400}, nil).Maybe()
	lp.EXPECT().Replay(mock.Anything, mock.Anything).Return(nil).Once()
	lp.EXPECT().Healthy().Return(nil).Once()

	cfg := NewLogPollerConfig(lp, orm, "verifier-1")
	reader, err := NewLogPollerSourceReader(ctx, testSourceReaderParams(t, stubHeadTracker{latest: 1000, finalized: 900}), cfg)
	require.NoError(t, err)
	r := reader.(*LogPollerSourceReader)
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	r.LoadFrom(501)
	require.Eventually(t, r.ready.Load, 10*time.Second, 10*time.Millisecond)

	stored, err := orm.LoadFilters(ctx)
	require.NoError(t, err)
	assert.Contains(t, stored, verifierFilterName("verifier-1", onRamp))
	assert.NotContains(t, stored, verifierFilterName("verifier-1", oldOnRamp), "the stale filter is gone")
	assert.Contains(t, stored, verifierFilterName("verifier-2", oldOnRamp), "another verifier's filter stays")
	assert.Len(t, stored, 2)

	otherStored, err := otherORM.LoadFilters(ctx)
	require.NoError(t, err)
	assert.Contains(t, otherStored, verifierFilterName("verifier-1", oldOnRamp), "another chain's filter stays")
}
