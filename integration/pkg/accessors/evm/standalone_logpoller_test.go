package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	_ "github.com/lib/pq" // sql driver; sql.Open does not connect
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

// eventLog records the order in which fakes are closed.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (e *eventLog) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, s)
}

func (e *eventLog) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

// fakeChainClient serves errors for every call the LogPoller makes, so a real LogPoller can run
// without a node.
type fakeChainClient struct {
	client.Client
	events *eventLog
}

var errFakeRPC = errors.New("fake rpc is unreachable")

func (f *fakeChainClient) Close() { f.events.add("chain client closed") }
func (*fakeChainClient) HeadByNumber(context.Context, *big.Int) (*evmtypes.Head, error) {
	return nil, errFakeRPC
}

func (*fakeChainClient) HeaderByNumberWithOpts(context.Context, *big.Int, evmtypes.HeaderByNumberOpts) (*evmtypes.Header, error) {
	return nil, errFakeRPC
}

func (*fakeChainClient) HeadByHash(context.Context, common.Hash) (*evmtypes.Head, error) {
	return nil, errFakeRPC
}
func (*fakeChainClient) BatchCallContext(context.Context, []rpc.BatchElem) error { return errFakeRPC }
func (*fakeChainClient) FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
	return nil, errFakeRPC
}
func (*fakeChainClient) ConfiguredChainID() *big.Int { return big.NewInt(1337) }
func (*fakeChainClient) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return nil, errFakeRPC
}

type fakeHeadTracker struct {
	heads.Tracker
	events *eventLog
}

func (f *fakeHeadTracker) Close() error {
	f.events.add("head tracker closed")
	return nil
}

func (*fakeHeadTracker) LatestAndFinalizedBlock(context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return nil, nil, errFakeRPC
}

func (*fakeHeadTracker) LatestSafeBlock(context.Context) (*evmtypes.Head, error) {
	return nil, errFakeRPC
}

var nextTestChainID atomic.Int64

// newTestChain builds a runtime over fakes for a chain ID no other test uses.
func newTestChain(t *testing.T, selector protocol.ChainSelector) (chain *standaloneChain, chainID string, events *eventLog) {
	t.Helper()
	chainID = newTestChainID()
	chain = newTestChainFor(t, selector, chainID)
	return chain, chainID, chain.chainClient.(*fakeChainClient).events
}

func newTestChainID() string { return strconv.FormatInt(920_000+nextTestChainID.Add(1), 10) }

// newTestChainFor builds a runtime over fakes for chainID. Its events are on the fakes it holds.
func newTestChainFor(t *testing.T, selector protocol.ChainSelector, chainID string) *standaloneChain {
	t.Helper()
	cfg, err := newChainlinkEVMConfig(evmconfig.Info{
		ChainID: chainID,
		Nodes:   []evmconfig.Node{{HTTPUrl: "http://127.0.0.1:1"}},
	})
	require.NoError(t, err)

	events := &eventLog{}
	return &standaloneChain{
		lggr:         logger.Test(t),
		selector:     selector,
		chainClient:  &fakeChainClient{events: events},
		chainConfig:  cfg,
		headTracker:  &fakeHeadTracker{events: events},
		newLogPoller: buildLogPoller,
		recoveryStop: make(services.StopChan),
	}
}

// newUnconnectedDB returns a pool that never connects: building a LogPoller must not touch it.
func newUnconnectedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fakeLogPoller records its close and fails Start or Close on demand.
type fakeLogPoller struct {
	logpoller.LogPoller
	events   *eventLog
	startErr error
	closeErr error
}

func (f *fakeLogPoller) Start(context.Context) error { return f.startErr }
func (f *fakeLogPoller) Close() error {
	f.events.add("log poller closed")
	return f.closeErr
}

func TestStandaloneChainLogPollerBuiltOnceAndShared(t *testing.T) {
	t.Parallel()
	chain, _, _ := newTestChain(t, 1)
	db := newUnconnectedDB(t)

	const callers = 16
	pollers := make([]logpoller.LogPoller, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			lp, err := chain.LogPoller(t.Context(), db)
			assert.NoError(t, err)
			pollers[i] = lp
		})
	}
	wg.Wait()

	require.NotNil(t, pollers[0])
	for i := 1; i < callers; i++ {
		require.Same(t, pollers[0], pollers[i])
	}
	require.NoError(t, chain.Close())
}

func TestStandaloneChainLogPollerRefusedAfterClose(t *testing.T) {
	t.Parallel()
	chain, _, _ := newTestChain(t, 1)
	require.NoError(t, chain.Close())

	_, err := chain.LogPoller(t.Context(), newUnconnectedDB(t))
	require.ErrorContains(t, err, "closed")
}

func TestStandaloneChainLogPollerRequiresDatabase(t *testing.T) {
	t.Parallel()
	chain, chainID, _ := newTestChain(t, 1)

	_, err := chain.LogPoller(t.Context(), nil)
	require.ErrorContains(t, err, "database")
	require.ErrorContains(t, err, "selector 1")
	require.ErrorContains(t, err, "evm_chain_id "+chainID)
}

func TestStandaloneChainLogPollerFailuresLeaveNoPoller(t *testing.T) {
	t.Parallel()
	errBuild := errors.New("metrics already registered")
	errStart := errors.New("start failed")

	for _, tc := range []struct {
		name  string
		build logPollerBuilder
		want  error
	}{
		{
			name:  "build",
			build: func(logPollerInputs) (logpoller.LogPoller, error) { return nil, errBuild },
			want:  errBuild,
		},
		{
			name: "start",
			build: func(logPollerInputs) (logpoller.LogPoller, error) {
				return &fakeLogPoller{events: &eventLog{}, startErr: errStart}, nil
			},
			want: errStart,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chain, chainID, _ := newTestChain(t, 1)
			chain.newLogPoller = tc.build

			lp, err := chain.LogPoller(t.Context(), newUnconnectedDB(t))
			require.ErrorIs(t, err, tc.want)
			require.ErrorContains(t, err, "selector 1")
			require.ErrorContains(t, err, "evm_chain_id "+chainID)
			require.Nil(t, lp)
			require.Nil(t, chain.logPoller)
			require.NoError(t, chain.Close())
		})
	}
}

func TestStandaloneChainLogPollerCloseErrorIsReturned(t *testing.T) {
	t.Parallel()
	errClose := errors.New("close failed")
	chain, chainID, _ := newTestChain(t, 1)
	chain.newLogPoller = func(logPollerInputs) (logpoller.LogPoller, error) {
		return &fakeLogPoller{events: &eventLog{}, closeErr: errClose}, nil
	}
	_, err := chain.LogPoller(t.Context(), newUnconnectedDB(t))
	require.NoError(t, err)

	err = chain.Close()
	require.ErrorIs(t, err, errClose)
	require.ErrorContains(t, err, "evm_chain_id "+chainID)
}

func TestStandaloneChainLogPollerAlreadyStoppedClosesCleanly(t *testing.T) {
	t.Parallel()
	chain, _, _ := newTestChain(t, 1)
	lp, err := chain.LogPoller(t.Context(), newUnconnectedDB(t))
	require.NoError(t, err)
	require.NoError(t, lp.Close(), "something other than the runtime stops the poller")

	require.NoError(t, chain.Close())
}

// The LogPoller reads heads from the head tracker, so it closes first.
func TestStandaloneChainCloseOrder(t *testing.T) {
	t.Parallel()
	chain, _, events := newTestChain(t, 1)
	chain.newLogPoller = func(logPollerInputs) (logpoller.LogPoller, error) {
		return &fakeLogPoller{events: events}, nil
	}
	chain.headTracker = &fakeHeadTracker{events: events}
	_, err := chain.LogPoller(t.Context(), newUnconnectedDB(t))
	require.NoError(t, err)

	require.NoError(t, chain.Close())
	require.Equal(t, []string{"log poller closed", "head tracker closed", "chain client closed"}, events.snapshot())
	require.NoError(t, chain.Close(), "Close stays idempotent")
}

// Building twice for one chain ID, the second time after a clean close, is the job-restart path.
// It also proves the real constructors register their metrics idempotently and leave no goroutines.
func TestStandaloneChainRealLogPollerRebuildsAndLeavesNoGoroutines(t *testing.T) {
	// Not parallel: goleak sees every goroutine in the process.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	db := newUnconnectedDB(t)
	chainID := newTestChainID()
	for range 2 {
		chain := newTestChainFor(t, 1, chainID)
		lp, err := chain.LogPoller(t.Context(), db)
		require.NoError(t, err)
		require.NotNil(t, lp)
		require.NoError(t, chain.Close())
	}
	require.NoError(t, db.Close())
}
