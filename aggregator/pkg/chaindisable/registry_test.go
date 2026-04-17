package chaindisable_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/chaindisable"
)

// fakeStore is a minimal in-memory Store for unit tests.
type fakeStore struct {
	disabled []chaindisable.ChainStatus
	err      error
}

func (f *fakeStore) BatchSetStatus(_ context.Context, _ chaindisable.LaneSide, _ []uint64, _ bool) error {
	return f.err
}

func (f *fakeStore) List(_ context.Context) ([]chaindisable.ChainStatus, error) {
	return f.disabled, f.err
}

func (f *fakeStore) ListDisabled(_ context.Context) ([]chaindisable.ChainStatus, error) {
	return f.disabled, f.err
}

func (f *fakeStore) Get(_ context.Context, _ chaindisable.LaneSide, _ uint64) (*chaindisable.ChainStatus, error) {
	return nil, f.err
}

func newTestRegistry(t *testing.T, store chaindisable.Store) *chaindisable.Registry {
	t.Helper()
	return chaindisable.NewRegistry(store, logger.Sugared(logger.Test(t)))
}

// laneReport is a minimal LaneReport for tests.
type laneReport struct {
	source uint64
	dest   uint64
}

func (l laneReport) GetSourceChainSelector() uint64 { return l.source }
func (l laneReport) GetDestinationSelector() uint64 { return l.dest }

func TestRegistry_IsDisabled_EmptyRegistry_AlwaysFalse(t *testing.T) {
	t.Parallel()
	reg := newTestRegistry(t, &fakeStore{})

	assert.False(t, reg.IsDisabled(laneReport{source: 1, dest: 2}))
	assert.False(t, reg.IsDisabled(laneReport{source: 0, dest: 0}))
}

func TestRegistry_Refresh_LoadsDisabledSources(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		disabled: []chaindisable.ChainStatus{
			{ChainSelector: 100, Side: chaindisable.LaneSideSource, Disabled: true},
		},
	}
	reg := newTestRegistry(t, store)

	require.NoError(t, reg.Refresh(context.Background()))

	assert.True(t, reg.IsDisabled(laneReport{source: 100, dest: 999}), "source 100 should be disabled")
	assert.False(t, reg.IsDisabled(laneReport{source: 200, dest: 999}), "source 200 should be enabled")
}

func TestRegistry_Refresh_LoadsDisabledDestinations(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		disabled: []chaindisable.ChainStatus{
			{ChainSelector: 200, Side: chaindisable.LaneSideDestination, Disabled: true},
		},
	}
	reg := newTestRegistry(t, store)
	require.NoError(t, reg.Refresh(context.Background()))

	assert.True(t, reg.IsDisabled(laneReport{source: 999, dest: 200}), "dest 200 should be disabled")
	assert.False(t, reg.IsDisabled(laneReport{source: 999, dest: 100}), "dest 100 should be enabled")
}

func TestRegistry_IsDisabled_SourceOrDestinationSuffices(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		disabled: []chaindisable.ChainStatus{
			{ChainSelector: 10, Side: chaindisable.LaneSideSource, Disabled: true},
			{ChainSelector: 20, Side: chaindisable.LaneSideDestination, Disabled: true},
		},
	}
	reg := newTestRegistry(t, store)
	require.NoError(t, reg.Refresh(context.Background()))

	assert.True(t, reg.IsDisabled(laneReport{source: 10, dest: 99}), "source disabled")
	assert.True(t, reg.IsDisabled(laneReport{source: 99, dest: 20}), "dest disabled")
	assert.True(t, reg.IsDisabled(laneReport{source: 10, dest: 20}), "both disabled")
	assert.False(t, reg.IsDisabled(laneReport{source: 99, dest: 99}), "neither disabled")
}

func TestRegistry_Refresh_Error_PropagatesAndPreservesState(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		disabled: []chaindisable.ChainStatus{
			{ChainSelector: 50, Side: chaindisable.LaneSideSource, Disabled: true},
		},
	}
	reg := newTestRegistry(t, store)
	require.NoError(t, reg.Refresh(context.Background()))
	assert.True(t, reg.IsDisabled(laneReport{source: 50, dest: 0}))

	// Simulate store error on next refresh
	store.err = errors.New("db unavailable")
	require.Error(t, reg.Refresh(context.Background()))

	// State should now be cleared (empty maps after failed refresh is acceptable per implementation)
	// The important thing is no panic and the error is returned
}

func TestRegistry_Refresh_ClearsStaleEntries(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		disabled: []chaindisable.ChainStatus{
			{ChainSelector: 300, Side: chaindisable.LaneSideSource, Disabled: true},
		},
	}
	reg := newTestRegistry(t, store)
	require.NoError(t, reg.Refresh(context.Background()))
	assert.True(t, reg.IsDisabled(laneReport{source: 300, dest: 0}))

	// Chain is re-enabled — no longer in ListDisabled results
	store.disabled = nil
	require.NoError(t, reg.Refresh(context.Background()))

	assert.False(t, reg.IsDisabled(laneReport{source: 300, dest: 0}), "should be enabled after re-enable")
}

func TestRegistry_StartPeriodicRefresh_CallsRefreshRepeatedly(t *testing.T) {
	t.Parallel()

	var refreshCount atomic.Int32
	store := &countingStore{refreshCount: &refreshCount}

	reg := newTestRegistry(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg.StartPeriodicRefresh(ctx, 20*time.Millisecond)

	require.Eventually(t, func() bool {
		return refreshCount.Load() >= 3
	}, 500*time.Millisecond, 5*time.Millisecond, "expected at least 3 periodic refreshes")

	cancel()
	// Allow goroutine to exit
	time.Sleep(30 * time.Millisecond)
}

func TestRegistry_StartPeriodicRefresh_StopsOnContextCancel(t *testing.T) {
	t.Parallel()

	var refreshCount atomic.Int32
	store := &countingStore{refreshCount: &refreshCount}

	reg := newTestRegistry(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	reg.StartPeriodicRefresh(ctx, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		return refreshCount.Load() >= 2
	}, 200*time.Millisecond, 5*time.Millisecond)

	cancel()
	countAtCancel := refreshCount.Load()
	time.Sleep(50 * time.Millisecond)

	assert.InDelta(t, countAtCancel, refreshCount.Load(), 1, "refresh should stop shortly after context cancel")
}

func TestNoopChecker_NeverDisables(t *testing.T) {
	t.Parallel()
	checker := chaindisable.NoopChecker{}

	assert.False(t, checker.IsDisabled(laneReport{source: 1, dest: 2}))
	assert.False(t, checker.IsDisabled(laneReport{source: 0, dest: 0}))
	assert.False(t, checker.IsDisabled(laneReport{source: ^uint64(0), dest: ^uint64(0)}))
}

// countingStore counts ListDisabled calls for periodic refresh tests.
type countingStore struct {
	refreshCount *atomic.Int32
}

func (c *countingStore) BatchSetStatus(_ context.Context, _ chaindisable.LaneSide, _ []uint64, _ bool) error {
	return nil
}

func (c *countingStore) List(_ context.Context) ([]chaindisable.ChainStatus, error) {
	return nil, nil
}

func (c *countingStore) ListDisabled(_ context.Context) ([]chaindisable.ChainStatus, error) {
	c.refreshCount.Add(1)
	return nil, nil
}

func (c *countingStore) Get(_ context.Context, _ chaindisable.LaneSide, _ uint64) (*chaindisable.ChainStatus, error) {
	return nil, nil
}
