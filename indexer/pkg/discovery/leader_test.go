package discovery

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/indexer/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

// fakeLocker gives the lock when free is true. Its leases fail the heartbeat when failHeartbeat is true.
type fakeLocker struct {
	free          atomic.Bool
	failHeartbeat atomic.Bool
	acquires      atomic.Int32
	releases      atomic.Int32
}

type fakeLease struct {
	l    *fakeLocker
	once sync.Once
}

func (l *fakeLocker) TryAcquireDiscoveryLock(context.Context, time.Duration) (common.DiscoveryLease, bool, error) {
	if !l.free.CompareAndSwap(true, false) {
		return nil, false, nil
	}
	l.acquires.Add(1)
	return &fakeLease{l: l}, true, nil
}

func (f *fakeLease) Heartbeat(context.Context) error {
	if f.l.failHeartbeat.Load() {
		return errors.New("connection lost")
	}
	return nil
}

func (f *fakeLease) Release() {
	f.once.Do(func() {
		f.l.releases.Add(1)
		f.l.free.Store(true)
	})
}

func newTestElector(t *testing.T, locker common.DiscoveryLocker, lease, heartbeat, acquire time.Duration) *LeaderElector {
	t.Helper()
	e, err := NewLeaderElector(locker, lease, heartbeat, acquire, logger.Test(t), monitoring.NewNoopIndexerMetricLabeler())
	require.NoError(t, err)
	return e
}

func TestNewLeaderElector_RejectsHeartbeatNotLessThanLease(t *testing.T) {
	_, err := NewLeaderElector(&fakeLocker{}, time.Second, time.Second, time.Second, logger.Test(t), monitoring.NewNoopIndexerMetricLabeler())
	require.Error(t, err)
}

func TestLeaderElector_FollowerWhenLockIsHeld(t *testing.T) {
	locker := &fakeLocker{} // not free
	e := newTestElector(t, locker, time.Second, 100*time.Millisecond, 20*time.Millisecond)
	var elected atomic.Bool
	e.OnElected(func(context.Context) { elected.Store(true) })
	e.Start(t.Context())
	defer e.Close()

	time.Sleep(200 * time.Millisecond)
	require.False(t, e.IsLeader())
	require.False(t, elected.Load())
}

func TestLeaderElector_DemotedOnHeartbeatErrorThenElectedAgain(t *testing.T) {
	locker := &fakeLocker{}
	locker.free.Store(true)
	e := newTestElector(t, locker, time.Second, 20*time.Millisecond, 20*time.Millisecond)

	var elections atomic.Int32
	callbackCtxs := make(chan context.Context, 10)
	e.OnElected(func(ctx context.Context) {
		elections.Add(1)
		callbackCtxs <- ctx
	})
	e.Start(t.Context())
	defer e.Close()

	require.Eventually(t, e.IsLeader, time.Second, 5*time.Millisecond)
	leaderCtx, _, ok := e.LeaderContext()
	require.True(t, ok)
	firstCallbackCtx := <-callbackCtxs

	locker.failHeartbeat.Store(true)
	require.Eventually(t, func() bool { return leaderCtx.Err() != nil }, time.Second, 5*time.Millisecond, "leader context must be cancelled on heartbeat failure")
	require.Error(t, firstCallbackCtx.Err(), "callback context must be cancelled on demotion")
	require.Eventually(t, func() bool { return locker.releases.Load() >= 1 }, time.Second, 5*time.Millisecond)

	locker.failHeartbeat.Store(false)
	require.Eventually(t, func() bool { return elections.Load() >= 2 && e.IsLeader() }, time.Second, 5*time.Millisecond)
}

func TestLeaderElector_CloseReleasesLock(t *testing.T) {
	locker := &fakeLocker{}
	locker.free.Store(true)
	e := newTestElector(t, locker, time.Second, 20*time.Millisecond, 20*time.Millisecond)
	e.Start(t.Context())
	require.Eventually(t, e.IsLeader, time.Second, 5*time.Millisecond)

	e.Close()
	require.False(t, e.IsLeader())
	require.Equal(t, int32(1), locker.releases.Load())
}

func TestLeaderElector_TwoReplicasOnOneDatabase(t *testing.T) {
	uri, cleanup := testutil.SetupTestPostgresURI(t)
	t.Cleanup(cleanup)
	newStore := func() *storage.PostgresStorage {
		s, err := storage.NewPostgresStorage(t.Context(), logger.Test(t), monitoring.NewNoopIndexerMonitoring(), uri, pg.DriverPostgres, pg.DBConfig{}, 0, 0)
		require.NoError(t, err)
		return s
	}

	a := newTestElector(t, newStore(), 2*time.Second, 200*time.Millisecond, 50*time.Millisecond)
	b := newTestElector(t, newStore(), 2*time.Second, 200*time.Millisecond, 50*time.Millisecond)
	a.Start(t.Context())
	b.Start(t.Context())
	t.Cleanup(a.Close)
	t.Cleanup(b.Close)

	require.Eventually(t, func() bool { return a.IsLeader() || b.IsLeader() }, 3*time.Second, 10*time.Millisecond)
	for range 10 {
		require.False(t, a.IsLeader() && b.IsLeader(), "only one replica may be leader")
		time.Sleep(50 * time.Millisecond)
	}

	leader, follower := a, b
	if b.IsLeader() {
		leader, follower = b, a
	}
	leader.Close()
	require.Eventually(t, follower.IsLeader, 3*time.Second, 10*time.Millisecond, "follower must take over after the leader stops")
}
