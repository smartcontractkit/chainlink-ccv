package evm

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// fakeDBLease records how often it was taken and released, and can block or fail TakeAndHold.
type fakeDBLease struct {
	takes, releases atomic.Int32
	take            func(ctx context.Context, onHeld func(error)) error
	onRelease       func()
}

func (f *fakeDBLease) TakeAndHold(ctx context.Context, onHeld func(error)) error {
	f.takes.Add(1)
	if f.take != nil {
		return f.take(ctx, onHeld)
	}
	return nil
}

func (f *fakeDBLease) Release() {
	f.releases.Add(1)
	if f.onRelease != nil {
		f.onRelease()
	}
}

func newTestEVMLease(t *testing.T, fake *fakeDBLease) (*evmLease, *sql.DB) {
	t.Helper()
	db := newUnconnectedDB(t)
	l := newEVMLease(logger.Test(t), lazy.New(func(context.Context) (*sql.DB, error) { return db, nil }))
	l.newLease = func(*sql.DB) dbLease { return fake }
	return l, db
}

func TestEVMLeaseIsTakenOncePerFactory(t *testing.T) {
	t.Parallel()
	fake := &fakeDBLease{}
	l, _ := newTestEVMLease(t, fake)
	l.retain()

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { assert.NoError(t, l.Acquire(t.Context(), nil)) })
	}
	wg.Wait()
	require.Equal(t, int32(1), fake.takes.Load())
	require.NoError(t, l.drop())
	require.Equal(t, int32(1), fake.releases.Load())
}

func TestEVMLeaseEveryWaitingAcquireHearsTheLeaseIsHeld(t *testing.T) {
	t.Parallel()
	fake := &fakeDBLease{take: func(ctx context.Context, onHeld func(error)) error {
		onHeld(errors.New("held"))
		<-ctx.Done()
		return ctx.Err()
	}}
	l, _ := newTestEVMLease(t, fake)
	ctx, cancel := context.WithCancel(t.Context())
	var heard [3]atomic.Bool
	var wg sync.WaitGroup
	acquire := func(i int) {
		wg.Go(func() {
			assert.ErrorIs(t, l.Acquire(ctx, func(err error) { heard[i].Store(err != nil) }), context.Canceled)
		})
	}
	acquire(0)
	acquire(1)
	require.Eventually(t, func() bool { return heard[0].Load() && heard[1].Load() }, time.Second, time.Millisecond)
	acquire(2) // arrives while the wait goes on
	require.Eventually(t, heard[2].Load, time.Second, time.Millisecond)

	cancel()
	wg.Wait()
	require.Equal(t, int32(1), fake.takes.Load(), "only one Acquire waits on the database at a time")
	require.NoError(t, l.drop())
	require.Zero(t, fake.releases.Load(), "a lease never taken is not released")
}

func TestEVMLeaseOnlyTheLastDropReleasesBeforeClosingTheDatabase(t *testing.T) {
	t.Parallel()
	fake := &fakeDBLease{}
	l, db := newTestEVMLease(t, fake)
	l.retain()
	l.retain()
	// The pool never connects (port 1), so an open pool fails to dial; only a closed one says so.
	var dbOpenAtRelease atomic.Bool
	fake.onRelease = func() {
		_, err := db.Conn(context.Background())
		dbOpenAtRelease.Store(err == nil || err.Error() != "sql: database is closed")
	}
	require.NoError(t, l.Acquire(t.Context(), nil))

	require.NoError(t, l.drop())
	require.Zero(t, fake.releases.Load(), "the other holder still holds the lease")
	require.NoError(t, l.drop())
	require.True(t, dbOpenAtRelease.Load(), "the lease is released while the database is still open")
	_, err := db.Conn(context.Background())
	require.EqualError(t, err, "sql: database is closed")
	require.NoError(t, l.drop(), "a drop with no holder left does nothing more")
	require.Equal(t, int32(1), fake.releases.Load())
}

func TestEVMLeaseLastDropOfAnUnusedFactoryConnectsNothing(t *testing.T) {
	t.Parallel()
	var derives atomic.Int32
	l := newEVMLease(logger.Test(t), lazy.New(func(context.Context) (*sql.DB, error) {
		derives.Add(1)
		return nil, errors.New("must not connect")
	}))
	l.retain()
	require.NoError(t, l.drop())
	require.Equal(t, int32(0), derives.Load())
}

func TestEVMLeaseAcquireInFlightDuringTheLastDropGivesTheLeaseBack(t *testing.T) {
	t.Parallel()
	unblock := make(chan struct{})
	fake := &fakeDBLease{take: func(context.Context, func(error)) error { <-unblock; return nil }}
	l, _ := newTestEVMLease(t, fake)
	l.retain()
	done := make(chan error, 1)
	go func() { done <- l.Acquire(context.Background(), nil) }()
	require.Eventually(t, func() bool { return fake.takes.Load() == 1 }, time.Second, time.Millisecond)

	require.NoError(t, l.drop(), "the last drop does not wait for the Acquire in flight")
	close(unblock)
	require.ErrorContains(t, <-done, "closed")
	require.Equal(t, int32(1), fake.releases.Load())
}
