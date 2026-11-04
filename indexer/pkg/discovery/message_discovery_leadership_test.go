package discovery

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeGate struct {
	mu            sync.Mutex
	ctx           context.Context
	electionCount uint64
}

func (g *fakeGate) LeaderContext() (context.Context, uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ctx, g.electionCount, g.ctx != nil
}

func (g *fakeGate) elect(ctx context.Context) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ctx = ctx //nolint:fatcontext // test fake for the elector
	g.electionCount++
}

func (g *fakeGate) demote() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ctx = nil //nolint:fatcontext // test fake for the elector
}

func TestAggregatorMessageDiscovery_FollowerDoesNotPoll(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cancel()
	ts.Discovery.leadership = &fakeGate{}

	ts.Discovery.Start(ts.Context)
	time.Sleep(300 * time.Millisecond) // six poll intervals
	require.Equal(t, 0, ts.MockReader.GetCallCount(), "a follower must not read from the aggregator")
	require.NoError(t, ts.Discovery.Close())
}

func TestAggregatorMessageDiscovery_NewLeaderLoadsCursorFromStorage(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cancel()
	gate := &fakeGate{}
	ts.Discovery.leadership = gate

	// Storage returns 0, and the in-memory cursor is older state from an earlier leadership.
	ts.Reader.SetSinceValue(99)

	ts.Discovery.Start(ts.Context)
	leaderCtx, demote := context.WithCancel(ts.Context)
	gate.elect(leaderCtx)

	require.Eventually(t, func() bool { return ts.MockReader.GetCallCount() > 0 }, 2*time.Second, 10*time.Millisecond)
	since, _ := ts.Reader.GetSinceValue()
	require.Equal(t, int64(0), since, "the new leader must use the cursor from storage")

	demote()
	gate.demote()
	time.Sleep(100 * time.Millisecond)
	calls := ts.MockReader.GetCallCount()
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, calls, ts.MockReader.GetCallCount(), "a demoted replica must stop polling")
	require.NoError(t, ts.Discovery.Close())
}
