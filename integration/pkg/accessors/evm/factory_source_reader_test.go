package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
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
	lp      logpoller.LogPoller
	lpErr   error
	lpCalls int
	gotDB   *sql.DB
	chainID *big.Int
}

func (r *lpStubRuntime) EVMChainID() *big.Int { return r.chainID }

func (r *lpStubRuntime) LogPoller(_ context.Context, db *sql.DB) (logpoller.LogPoller, error) {
	r.lpCalls++
	r.gotDB = db
	return r.lp, r.lpErr
}

func (*lpStubRuntime) StartLogPoller(context.Context) error { return nil }

func newSourceFactory(t *testing.T, runtime chainRuntime) chainaccess.AccessorFactory {
	t.Helper()
	return newFactory(
		logger.Test(t),
		map[protocol.ChainSelector]string{testSourceSelector: validTestOffRampAddress},
		nil,
		nil,
		nil,
		nil,
		0,
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
	acc := got.(*accessor)
	acc.db = staticDatabase(&sql.DB{})
	return acc
}

// staticDatabase is a lazy database that returns db without connecting.
func staticDatabase(db *sql.DB) *lazy.Lazy[*sql.DB] {
	return lazy.New(func(context.Context) (*sql.DB, error) { return db, nil })
}

func TestAccessorSourceReaderConcurrentCallsShareOneReader(t *testing.T) {
	t.Parallel()

	acc := newSourceAccessor(t, newStubRuntime(t))
	require.False(t, acc.sourceBuilt, "GetAccessor must not build the reader")
	readers := make([]chainaccess.SourceReader, 8)
	var wg sync.WaitGroup
	for i := range readers {
		wg.Go(func() {
			r, err := acc.SourceReader()
			assert.NoError(t, err)
			readers[i] = r
		})
	}
	wg.Wait()
	for _, r := range readers {
		require.Same(t, readers[0], r)
	}
}

// newLogPollerAccessor is a source accessor with log_poller_enabled on for verifier-1.
func newLogPollerAccessor(t *testing.T, runtime chainRuntime) *accessor {
	t.Helper()
	acc := newSourceAccessor(t, runtime)
	acc.logPollerEnabled = true
	acc.verifierID = "verifier-1"
	acc.lease = newEVMLease(logger.Test(t), acc.db)
	return acc
}

func TestLogPollerOnSelectsLogPollerReader(t *testing.T) {
	t.Parallel()

	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID}
	acc := newLogPollerAccessor(t, runtime)
	db := &sql.DB{}
	acc.db = staticDatabase(db)

	reader, err := acc.SourceReader()
	require.NoError(t, err)
	require.IsType(t, &LogPollerSourceReader{}, reader)
	require.Equal(t, 1, runtime.lpCalls)
	require.Same(t, db, runtime.gotDB)

	again, err := acc.SourceReader()
	require.NoError(t, err)
	require.Same(t, reader, again)
	require.Equal(t, 1, runtime.lpCalls)
}

func TestLogPollerOffNeverBuildsALogPoller(t *testing.T) {
	t.Parallel()

	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID}
	acc := newSourceAccessor(t, runtime)

	reader, err := acc.SourceReader()
	require.NoError(t, err)
	require.IsType(t, &SourceReader{}, reader)
	require.Zero(t, runtime.lpCalls)
}

func TestLogPollerOnFailureDoesNotFallBackToTheRPCReader(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("build failed")
	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lpErr: wantErr, chainID: stubChainID}
	acc := newLogPollerAccessor(t, runtime)

	reader, err := acc.SourceReader()
	require.ErrorIs(t, err, wantErr)
	require.Nil(t, reader)
}

func TestLogPollerOnNeedsAVerifierID(t *testing.T) {
	t.Parallel()

	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID}
	acc := newLogPollerAccessor(t, runtime)
	acc.verifierID = ""

	_, err := acc.SourceReader()
	require.ErrorContains(t, err, "verifier_id")
	require.Zero(t, runtime.lpCalls)
}

func TestExecutorStyleAccessorNeverBuildsALogPoller(t *testing.T) {
	t.Parallel()

	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID}
	acc := newAccessor(logger.Test(t), testSourceSelector, runtime, [20]byte{1}, "key", nil, nil, nil, nil, nil, nil).(*accessor)
	acc.logPollerEnabled = true
	acc.verifierID = "verifier-1"

	_, err := acc.SourceReader()
	require.ErrorContains(t, err, "source reader not available")
	require.Zero(t, runtime.lpCalls)
}

// startRecordingRuntime records StartLogPoller into events.
type startRecordingRuntime struct {
	*lpStubRuntime
	events *[]string
}

func (r startRecordingRuntime) StartLogPoller(context.Context) error {
	*r.events = append(*r.events, "start")
	return nil
}

func TestLogPollerReaderStartTakesTheLeaseBeforeStartingTheLogPoller(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		takeErr error
		want    []string
	}{
		{name: "lease taken", want: []string{"acquire", "start"}},
		{name: "lease not taken", takeErr: errors.New("lease lost"), want: []string{"acquire"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var events []string
			runtime := startRecordingRuntime{
				lpStubRuntime: &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: stubChainID},
				events:        &events,
			}
			acc := newLogPollerAccessor(t, runtime)
			acc.lease.newLease = func(*sql.DB) dbLease {
				return &fakeDBLease{take: func(context.Context, func(error)) error {
					events = append(events, "acquire")
					return tt.takeErr
				}}
			}

			reader, err := acc.SourceReader()
			require.NoError(t, err)
			start := reader.(*LogPollerSourceReader).cfg.Start
			require.NotNil(t, start)
			require.Empty(t, events, "building the reader takes no lease and starts nothing")

			require.ErrorIs(t, start(t.Context(), nil), tt.takeErr)
			require.Equal(t, tt.want, events)
		})
	}
}

func TestTheLastAccessorCloseReleasesTheFactoryLeaseAfterItsRuntime(t *testing.T) {
	t.Parallel()
	runtime := newStubRuntime(t)
	f := newSourceFactory(t, runtime).(*factory)
	fake := &fakeDBLease{}
	f.lease, _ = newTestEVMLease(t, fake)
	var closesAtRelease int
	fake.onRelease = func() { closesAtRelease = runtime.closeCalls }
	first, err := f.GetAccessor(t.Context(), testSourceSelector)
	require.NoError(t, err)
	second, err := f.GetAccessor(t.Context(), testSourceSelector)
	require.NoError(t, err)
	require.NoError(t, f.lease.Acquire(t.Context(), nil))

	require.NoError(t, first.Close())
	require.NoError(t, first.Close(), "a second Close drops nothing more")
	require.Zero(t, fake.releases.Load(), "the other accessor still holds the lease")
	require.NoError(t, second.Close())
	require.Equal(t, int32(1), fake.releases.Load())
	require.Equal(t, runtime.closeCalls, closesAtRelease, "the lease is released after the last runtime closes")
}
