package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func setupChainStatusTestDB(t *testing.T) (*DatabaseStorage, func()) {
	t.Helper()
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	if err := RunMigrations(ds, "postgres"); err != nil {
		cleanup()
		t.Fatalf("run migrations: %v", err)
	}
	return NewDatabaseStorage(ds, 10, 10*time.Second, logger.Sugared(logger.Test(t))), cleanup
}

func TestDatabaseStorage_BatchSetStatus_Disable(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{1001, 1002}, true)
	require.NoError(t, err)

	s1, err := storage.Get(ctx, chainstatus.LaneSideSource, 1001)
	require.NoError(t, err)
	require.NotNil(t, s1)
	assert.True(t, s1.Disabled)
	assert.Equal(t, chainstatus.LaneSideSource, s1.Side)
	assert.Equal(t, uint64(1001), s1.ChainSelector)
	assert.False(t, s1.UpdatedAt.IsZero())

	s2, err := storage.Get(ctx, chainstatus.LaneSideSource, 1002)
	require.NoError(t, err)
	require.NotNil(t, s2)
	assert.True(t, s2.Disabled)
}

func TestDatabaseStorage_BatchSetStatus_Enable(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{2001}, true))
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{2001}, false))

	s, err := storage.Get(ctx, chainstatus.LaneSideSource, 2001)
	require.NoError(t, err)
	require.NotNil(t, s, "row should exist for audit trail after re-enable")
	assert.False(t, s.Disabled)
}

func TestDatabaseStorage_BatchSetStatus_Idempotent(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{3001}, true))
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{3001}, true))

	s, err := storage.Get(ctx, chainstatus.LaneSideSource, 3001)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.True(t, s.Disabled)
}

func TestDatabaseStorage_BatchSetStatus_EmptySelectors(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	err := storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{}, true)
	require.NoError(t, err)
}

func TestDatabaseStorage_BatchSetStatus_SourceAndDestinationAreIndependent(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{4001}, true))
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideDestination, []uint64{4001}, true))

	src, err := storage.Get(ctx, chainstatus.LaneSideSource, 4001)
	require.NoError(t, err)
	require.NotNil(t, src)
	assert.True(t, src.Disabled)
	assert.Equal(t, chainstatus.LaneSideSource, src.Side)

	dst, err := storage.Get(ctx, chainstatus.LaneSideDestination, 4001)
	require.NoError(t, err)
	require.NotNil(t, dst)
	assert.True(t, dst.Disabled)
	assert.Equal(t, chainstatus.LaneSideDestination, dst.Side)
}

func TestDatabaseStorage_Get_NoRow_ReturnsNil(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	s, err := storage.Get(ctx, chainstatus.LaneSideSource, 9999)
	require.NoError(t, err)
	assert.Nil(t, s, "no row should return nil (= enabled by default)")
}

func TestDatabaseStorage_Get_WrongSide_ReturnsNil(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{5001}, true))

	s, err := storage.Get(ctx, chainstatus.LaneSideDestination, 5001)
	require.NoError(t, err)
	assert.Nil(t, s)
}

func TestDatabaseStorage_List_Empty(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	statuses, err := storage.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, statuses)
}

func TestDatabaseStorage_List_ReturnsAllRows(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{6001}, true))
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideDestination, []uint64{6002}, true))
	// Re-enable one — should still appear in List
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{6001}, false))

	statuses, err := storage.List(ctx)
	require.NoError(t, err)
	require.Len(t, statuses, 2, "List should return all rows including re-enabled ones")

	byKey := make(map[string]chainstatus.ChainStatus)
	for _, s := range statuses {
		byKey[string(s.Side)+":"+string(rune(s.ChainSelector))] = s
	}

	// Verify re-enabled chain appears with Disabled=false
	found6001 := false
	found6002 := false
	for _, s := range statuses {
		if s.ChainSelector == 6001 && s.Side == chainstatus.LaneSideSource {
			assert.False(t, s.Disabled)
			found6001 = true
		}
		if s.ChainSelector == 6002 && s.Side == chainstatus.LaneSideDestination {
			assert.True(t, s.Disabled)
			found6002 = true
		}
	}
	assert.True(t, found6001)
	assert.True(t, found6002)
}

func TestDatabaseStorage_ListDisabled_OnlyDisabled(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{7001, 7002}, true))
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideDestination, []uint64{7003}, true))
	// Re-enable 7002 — should not appear in ListDisabled
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{7002}, false))

	statuses, err := storage.ListDisabled(ctx)
	require.NoError(t, err)

	for _, s := range statuses {
		assert.True(t, s.Disabled, "ListDisabled must only return disabled rows")
		assert.NotEqual(t, uint64(7002), s.ChainSelector, "re-enabled chain should not appear")
	}

	selectors := make(map[uint64]bool)
	for _, s := range statuses {
		selectors[s.ChainSelector] = true
	}
	assert.True(t, selectors[7001])
	assert.True(t, selectors[7003])
	assert.Len(t, statuses, 2)
}

func TestDatabaseStorage_ListDisabled_Empty(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	statuses, err := storage.ListDisabled(ctx)
	require.NoError(t, err)
	assert.Empty(t, statuses)
}

func TestDatabaseStorage_ChainStatus_UpdatedAt_ChangesOnUpdate(t *testing.T) {
	t.Parallel()
	storage, cleanup := setupChainStatusTestDB(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{8001}, true))
	s1, err := storage.Get(ctx, chainstatus.LaneSideSource, 8001)
	require.NoError(t, err)
	require.NotNil(t, s1)

	// Small sleep to ensure updated_at changes
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, storage.BatchSetStatus(ctx, chainstatus.LaneSideSource, []uint64{8001}, false))
	s2, err := storage.Get(ctx, chainstatus.LaneSideSource, 8001)
	require.NoError(t, err)
	require.NotNil(t, s2)

	assert.True(t, s2.UpdatedAt.After(s1.UpdatedAt) || s2.UpdatedAt.Equal(s1.UpdatedAt),
		"updated_at should not go backwards")
}
