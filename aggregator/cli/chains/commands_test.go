package chains

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ---- in-memory Store ------------------------------------------------------

type memStore struct {
	rows map[storeKey]*chainstatus.ChainStatus
}

type storeKey struct {
	selector uint64
	side     chainstatus.LaneSide
}

func newMemStore() *memStore {
	return &memStore{rows: make(map[storeKey]*chainstatus.ChainStatus)}
}

func (m *memStore) BatchSetStatus(_ context.Context, side chainstatus.LaneSide, selectors []uint64, disabled bool) error {
	for _, sel := range selectors {
		m.rows[storeKey{sel, side}] = &chainstatus.ChainStatus{
			ChainSelector: sel,
			Side:          side,
			Disabled:      disabled,
			UpdatedAt:     time.Now(),
		}
	}
	return nil
}

func (m *memStore) List(_ context.Context) ([]chainstatus.ChainStatus, error) {
	out := make([]chainstatus.ChainStatus, 0, len(m.rows))
	for _, v := range m.rows {
		out = append(out, *v)
	}
	return out, nil
}

func (m *memStore) ListDisabled(_ context.Context) ([]chainstatus.ChainStatus, error) {
	var out []chainstatus.ChainStatus
	for _, v := range m.rows {
		if v.Disabled {
			out = append(out, *v)
		}
	}
	return out, nil
}

func (m *memStore) Get(_ context.Context, side chainstatus.LaneSide, selector uint64) (*chainstatus.ChainStatus, error) {
	if v, ok := m.rows[storeKey{selector, side}]; ok {
		s := *v
		return &s, nil
	}
	return nil, nil
}

// ---- helpers --------------------------------------------------------------

func makeDeps(t *testing.T, store chainstatus.Store, committee *model.Committee) Deps {
	t.Helper()
	return Deps{Logger: logger.Test(t), Store: store, Committee: committee}
}

// makeCommittee builds a Committee from explicit source and destination selector slices.
func makeCommittee(sources, dests []uint64) *model.Committee {
	c := &model.Committee{
		QuorumConfigs:        make(map[string]*model.QuorumConfig, len(sources)),
		DestinationVerifiers: make(map[string]string, len(dests)),
	}
	for _, sel := range sources {
		c.QuorumConfigs[strconv.FormatUint(sel, 10)] = nil
	}
	for _, sel := range dests {
		c.DestinationVerifiers[strconv.FormatUint(sel, 10)] = "0x0"
	}
	return c
}

// runCLI invokes chains commands with args, captures stdout, and returns combined output + error.
func runCLI(t *testing.T, deps Deps, args []string) (string, error) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	app := cli.NewApp()
	app.Name = "test"
	app.Commands = InitChainsCommands(deps)
	runErr := app.Run(append([]string{"test"}, args...))

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), runErr
}

// ---- list tests -----------------------------------------------------------

func TestList_EmptyDBEmptyCommittee(t *testing.T) {
	out, err := runCLI(t, makeDeps(t, newMemStore(), nil), []string{"list"})
	require.NoError(t, err)
	assert.Contains(t, out, "No chain status rows found.")
}

func TestList_EmptyDB_ShowsCommitteeChains(t *testing.T) {
	committee := makeCommittee([]uint64{1001, 1002}, []uint64{2001})
	out, err := runCLI(t, makeDeps(t, newMemStore(), committee), []string{"list"})
	require.NoError(t, err)
	assert.Contains(t, out, "1001", "source 1001 should appear")
	assert.Contains(t, out, "1002", "source 1002 should appear")
	assert.Contains(t, out, "2001", "dest 2001 should appear")
	// All should show as enabled (no DB row).
	assert.NotContains(t, out, "true", "no chain should be disabled")
}

func TestList_MergesDBRowsWithCommittee(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	require.NoError(t, store.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{1001}, true))

	// Committee has 1001 (in DB as disabled) and 1002 (not in DB).
	committee := makeCommittee([]uint64{1001, 1002}, nil)
	out, err := runCLI(t, makeDeps(t, store, committee), []string{"list"})
	require.NoError(t, err)
	assert.Contains(t, out, "1001")
	assert.Contains(t, out, "1002", "1002 has no DB row but should still appear")
	assert.Contains(t, out, "true", "1001 should be shown as disabled")
}

func TestList_NoDuplicates(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	require.NoError(t, store.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{1001}, false))

	// Committee also contains 1001 as a source.
	committee := makeCommittee([]uint64{1001}, nil)
	out, err := runCLI(t, makeDeps(t, store, committee), []string{"list"})
	require.NoError(t, err)

	// Count occurrences of "1001" in the output — should appear exactly once.
	count := bytes.Count([]byte(out), []byte("1001"))
	assert.Equal(t, 1, count, "selector 1001 should appear exactly once; got output:\n%s", out)
}

func TestList_OnlyDisabled_FilterWorks(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	require.NoError(t, store.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{1001}, true))

	// Committee has 1001 (disabled) and 1002 (enabled, no DB row).
	committee := makeCommittee([]uint64{1001, 1002}, nil)
	out, err := runCLI(t, makeDeps(t, store, committee), []string{"list", "--only-disabled"})
	require.NoError(t, err)
	assert.Contains(t, out, "1001")
	assert.NotContains(t, out, "1002", "enabled chain should be filtered out by --only-disabled")
}

func TestList_OnlyDisabled_NoneDisabled(t *testing.T) {
	committee := makeCommittee([]uint64{1001}, nil)
	out, err := runCLI(t, makeDeps(t, newMemStore(), committee), []string{"list", "--only-disabled"})
	require.NoError(t, err)
	assert.Contains(t, out, "No chain status rows found.")
}

// ---- disable / enable tests -----------------------------------------------

func TestDisable_Source(t *testing.T) {
	store := newMemStore()
	out, err := runCLI(t, makeDeps(t, store, nil), []string{"disable", "--source", "1001"})
	require.NoError(t, err)
	assert.Contains(t, out, "disabled")

	s, err := store.Get(context.Background(), chainstatus.LaneSideSource, 1001)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.True(t, s.Disabled)
}

func TestDisable_Destination(t *testing.T) {
	store := newMemStore()
	out, err := runCLI(t, makeDeps(t, store, nil), []string{"disable", "--destination", "2001"})
	require.NoError(t, err)
	assert.Contains(t, out, "disabled")

	s, err := store.Get(context.Background(), chainstatus.LaneSideDestination, 2001)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.True(t, s.Disabled)
}

func TestDisable_All(t *testing.T) {
	store := newMemStore()
	committee := makeCommittee([]uint64{1001, 1002}, []uint64{2001})
	out, err := runCLI(t, makeDeps(t, store, committee), []string{"disable", "--all"})
	require.NoError(t, err)
	assert.Contains(t, out, "disabled")

	ctx := context.Background()
	for _, sel := range []uint64{1001, 1002} {
		s, err := store.Get(ctx, chainstatus.LaneSideSource, sel)
		require.NoError(t, err)
		require.NotNil(t, s, fmt.Sprintf("source %d should be disabled", sel))
		assert.True(t, s.Disabled)
	}
	s, err := store.Get(ctx, chainstatus.LaneSideDestination, 2001)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.True(t, s.Disabled)
}

func TestDisable_NoFlags_ReturnsError(t *testing.T) {
	_, err := runCLI(t, makeDeps(t, newMemStore(), nil), []string{"disable"})
	require.Error(t, err)
}

func TestEnable_Source(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	require.NoError(t, store.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{1001}, true))

	out, err := runCLI(t, makeDeps(t, store, nil), []string{"enable", "--source", "1001"})
	require.NoError(t, err)
	assert.Contains(t, out, "enabled")

	s, err := store.Get(ctx, chainstatus.LaneSideSource, 1001)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.False(t, s.Disabled)
}

// ---- get tests ------------------------------------------------------------

func TestGet_ExistingRow(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	require.NoError(t, store.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{1001}, true))

	out, err := runCLI(t, makeDeps(t, store, nil), []string{"get", "--source", "1001"})
	require.NoError(t, err)
	assert.Contains(t, out, "1001")
	assert.Contains(t, out, "true")
}

func TestGet_NoRow_ShowsSyntheticEnabled(t *testing.T) {
	out, err := runCLI(t, makeDeps(t, newMemStore(), nil), []string{"get", "--source", "9999"})
	require.NoError(t, err)
	assert.Contains(t, out, "9999")
	assert.Contains(t, out, "false", "unknown selector should show as enabled")
}

func TestGet_NoFlags_ReturnsError(t *testing.T) {
	_, err := runCLI(t, makeDeps(t, newMemStore(), nil), []string{"get"})
	require.Error(t, err)
}
