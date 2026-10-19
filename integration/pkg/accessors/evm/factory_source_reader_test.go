package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
)

// stubChainID is the EVM chain ID tests give a stub runtime that does not care which chain it is.
var stubChainID = big.NewInt(910_000)

const testSourceSelector = protocol.ChainSelector(5009297550715157269)

// lpStubRuntime is a chain runtime that can also host a LogPoller.
type lpStubRuntime struct {
	*stubChainRuntime
	lp       logpoller.LogPoller
	lpErr    error
	lpCalls  int
	gotDB    *sql.DB
	startCtx context.Context
	chainID  *big.Int
}

func (r *lpStubRuntime) EVMChainID() *big.Int { return r.chainID }

func (r *lpStubRuntime) LogPoller(ctx context.Context, db *sql.DB) (logpoller.LogPoller, error) {
	r.lpCalls++
	r.gotDB = db
	r.startCtx = ctx //nolint:fatcontext // the test inspects the context the accessor passed
	return r.lp, r.lpErr
}

func newSourceFactory(t *testing.T, runtime chainRuntime) chainaccess.AccessorFactory {
	t.Helper()
	return newFactory(
		logger.Test(t),
		map[protocol.ChainSelector]string{testSourceSelector: validTestOffRampAddress},
		nil,
		nil,
		0,
		func(context.Context, protocol.ChainSelector, logger.Logger) (chainRuntime, error) {
			return runtime, nil
		},
	)
}

func newStubRuntime(t *testing.T) *stubChainRuntime {
	t.Helper()
	return &stubChainRuntime{Client: clienttest.NewClient(t), Tracker: heads.NullTracker}
}

func newSourceAccessor(t *testing.T, runtime chainRuntime) *accessor {
	t.Helper()
	got, err := newSourceFactory(t, runtime).GetAccessor(t.Context(), testSourceSelector)
	require.NoError(t, err)
	return got.(*accessor)
}

func TestAccessorSourceReaderIsBuiltLazilyAndOnce(t *testing.T) {
	t.Parallel()

	acc := newSourceAccessor(t, newStubRuntime(t))
	require.False(t, acc.sourceBuilt, "GetAccessor must not build the reader")

	first, err := acc.SourceReader()
	require.NoError(t, err)
	require.IsType(t, &SourceReader{}, first)
	second, err := acc.SourceReader()
	require.NoError(t, err)
	require.Same(t, first, second)
}

func TestAccessorSourceReaderConcurrentCallsShareOneReader(t *testing.T) {
	t.Parallel()

	acc := newSourceAccessor(t, newStubRuntime(t))
	readers := make([]chainaccess.SourceReader, 8)
	var wg sync.WaitGroup
	for i := range readers {
		wg.Go(func() {
			r, err := acc.SourceReader()
			require.NoError(t, err)
			readers[i] = r
		})
	}
	wg.Wait()
	for _, r := range readers {
		require.Same(t, readers[0], r)
	}
}

func TestSetSourceReaderDepsSelectsLogPollerReader(t *testing.T) {
	t.Parallel()

	lp := lpmocks.NewLogPoller(t)
	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lp, chainID: stubChainID}
	acc := newSourceAccessor(t, runtime)
	db := &sql.DB{}

	require.NoError(t, acc.SetSourceReaderDeps(db, "verifier-1"))
	require.Equal(t, 1, runtime.lpCalls)
	require.Same(t, db, runtime.gotDB)

	reader, err := acc.SourceReader()
	require.NoError(t, err)
	require.IsType(t, &LogPollerSourceReader{}, reader)
	again, err := acc.SourceReader()
	require.NoError(t, err)
	require.Same(t, reader, again)

	// The same call again is a no-op, a different one is refused.
	require.NoError(t, acc.SetSourceReaderDeps(db, "verifier-1"))
	require.Equal(t, 1, runtime.lpCalls)
	require.Error(t, acc.SetSourceReaderDeps(db, "verifier-2"))
}

func TestSetSourceReaderDepsIsRefusedOnceTheReaderIsBuilt(t *testing.T) {
	t.Parallel()

	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID}
	acc := newSourceAccessor(t, runtime)
	reader, err := acc.SourceReader()
	require.NoError(t, err)

	require.ErrorContains(t, acc.SetSourceReaderDeps(&sql.DB{}, "verifier-1"), "already built")
	require.Zero(t, runtime.lpCalls)
	again, err := acc.SourceReader()
	require.NoError(t, err)
	require.Same(t, reader, again)
}

func TestSetSourceReaderDepsFailureKeepsTheRPCReader(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("another runtime owns this chain")
	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lpErr: wantErr, chainID: stubChainID}
	acc := newSourceAccessor(t, runtime)

	require.ErrorIs(t, acc.SetSourceReaderDeps(&sql.DB{}, "verifier-1"), wantErr)
	reader, err := acc.SourceReader()
	require.NoError(t, err)
	require.IsType(t, &SourceReader{}, reader)
}

func TestSetSourceReaderDepsNeedsARuntimeThatHostsALogPoller(t *testing.T) {
	t.Parallel()

	acc := newSourceAccessor(t, newStubRuntime(t))
	require.ErrorContains(t, acc.SetSourceReaderDeps(&sql.DB{}, "verifier-1"), "cannot host a LogPoller")
}

func TestExecutorStyleAccessorNeverBuildsALogPoller(t *testing.T) {
	t.Parallel()

	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID}
	acc := newAccessor(logger.Test(t), testSourceSelector, runtime, [20]byte{1}, "key", nil, nil, nil).(*accessor)

	_, err := acc.SourceReader()
	require.ErrorContains(t, err, "source reader not available")
	require.ErrorContains(t, acc.SetSourceReaderDeps(&sql.DB{}, "verifier-1"), "no source reader")
	require.Zero(t, runtime.lpCalls)
}

func TestAccessorCloseEndsTheLogPollerStartContext(t *testing.T) {
	t.Parallel()

	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID}
	acc := newSourceAccessor(t, runtime)
	require.NoError(t, acc.SetSourceReaderDeps(&sql.DB{}, "verifier-1"))
	require.NoError(t, runtime.startCtx.Err())

	require.NoError(t, acc.Close())
	require.Error(t, runtime.startCtx.Err())
}
