package chainstatus

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestPostgresChainStatusManager(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	store := NewPostgresChainStatusStore(db, lggr)
	ctx := t.Context()

	t.Run("write and read single chain status", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-single-chain")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-single-chain'")

		statuses := []protocol.ChainStatusInfo{
			{
				ChainSelector:        1,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		}
		err := manager.WriteChainStatuses(ctx, statuses)
		require.NoError(t, err)

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
		require.NoError(t, err)
		require.Len(t, result, 1)

		assert.Equal(t, protocol.ChainSelector(1), result[1].ChainSelector)
		assert.Equal(t, 0, big.NewInt(100).Cmp(result[1].FinalizedBlockHeight))
		assert.False(t, result[1].Disabled)
	})

	t.Run("write and read multiple chain statuses", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-multiple-chains")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-multiple-chains'")

		statuses := []protocol.ChainStatusInfo{
			{
				ChainSelector:        1,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
			{
				ChainSelector:        2,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             true,
			},
		}
		err := manager.WriteChainStatuses(ctx, statuses)
		require.NoError(t, err)

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1, 2})
		require.NoError(t, err)
		require.Len(t, result, 2)

		assert.Equal(t, protocol.ChainSelector(1), result[1].ChainSelector)
		assert.Equal(t, 0, big.NewInt(100).Cmp(result[1].FinalizedBlockHeight))
		assert.False(t, result[1].Disabled)

		assert.Equal(t, protocol.ChainSelector(2), result[2].ChainSelector)
		assert.Equal(t, 0, big.NewInt(200).Cmp(result[2].FinalizedBlockHeight))
		assert.True(t, result[2].Disabled)
	})

	t.Run("read only requested chain selectors", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-selective-read")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-selective-read'")

		statuses := []protocol.ChainStatusInfo{
			{
				ChainSelector:        1,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
			{
				ChainSelector:        2,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             true,
			},
		}
		err := manager.WriteChainStatuses(ctx, statuses)
		require.NoError(t, err)

		// Only read chain 1
		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
		require.NoError(t, err)
		require.Len(t, result, 1)

		assert.Equal(t, protocol.ChainSelector(1), result[1].ChainSelector)
		assert.Equal(t, 0, big.NewInt(100).Cmp(result[1].FinalizedBlockHeight))
		assert.False(t, result[1].Disabled)
	})

	t.Run("upsert updates existing chain status", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-upsert")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-upsert'")

		// Initial write
		initialStatus := []protocol.ChainStatusInfo{
			{
				ChainSelector:        1,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		}
		err := manager.WriteChainStatuses(ctx, initialStatus)
		require.NoError(t, err)

		// Update with new values
		updatedStatus := []protocol.ChainStatusInfo{
			{
				ChainSelector:        1,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             true,
			},
		}
		err = manager.WriteChainStatuses(ctx, updatedStatus)
		require.NoError(t, err)

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
		require.NoError(t, err)
		require.Len(t, result, 1)

		assert.Equal(t, protocol.ChainSelector(1), result[1].ChainSelector)
		assert.Equal(t, 0, big.NewInt(200).Cmp(result[1].FinalizedBlockHeight))
		assert.True(t, result[1].Disabled)
	})

	t.Run("read non-existent chain selectors returns empty map", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-nonexistent")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-nonexistent'")

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{999})
		require.NoError(t, err)
		require.Len(t, result, 0)
	})

	t.Run("read with empty selectors returns empty map", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-empty-selectors")

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{})
		require.NoError(t, err)
		require.Len(t, result, 0)
	})

	t.Run("write empty statuses does not error", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-empty-write")

		err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{})
		require.NoError(t, err)

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{})
		require.NoError(t, err)
		require.Len(t, result, 0)
	})

	t.Run("nil block height returns error", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-nil-block")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-nil-block'")

		statuses := []protocol.ChainStatusInfo{
			{
				ChainSelector:        1,
				FinalizedBlockHeight: nil,
				Disabled:             false,
			},
		}
		err := manager.WriteChainStatuses(ctx, statuses)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "finalized block height cannot be nil")
	})

	t.Run("multiple verifiers isolation", func(t *testing.T) {
		verifierID1 := "verifier-1"
		verifierID2 := "verifier-2"

		manager1 := NewPostgresChainStatusManager(store, verifierID1)
		manager2 := NewPostgresChainStatusManager(store, verifierID2)

		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id IN ($1, $2)", verifierID1, verifierID2)

		chainSelector := protocol.ChainSelector(1337)

		// Write status for verifier 1
		err := manager1.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// Write different status for verifier 2 on same chain
		err = manager2.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             true,
			},
		})
		require.NoError(t, err)

		// Read from verifier 1
		result1, err := manager1.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		require.Len(t, result1, 1)
		assert.Equal(t, big.NewInt(100), result1[chainSelector].FinalizedBlockHeight)
		assert.False(t, result1[chainSelector].Disabled)

		// Read from verifier 2
		result2, err := manager2.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		require.Len(t, result2, 1)
		assert.Equal(t, big.NewInt(200), result2[chainSelector].FinalizedBlockHeight)
		assert.True(t, result2[chainSelector].Disabled)

		// Verify they don't interfere with each other
		assert.NotEqual(t, result1[chainSelector].FinalizedBlockHeight, result2[chainSelector].FinalizedBlockHeight)
		assert.NotEqual(t, result1[chainSelector].Disabled, result2[chainSelector].Disabled)
	})
}

func TestPostgresChainStatusStore_List(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	ctx := t.Context()
	store := NewPostgresChainStatusStore(db, lggr)
	manager := NewPostgresChainStatusManager(store, "store-list-verifier")
	_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'store-list-verifier'")

	err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{ChainSelector: 1, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
		{ChainSelector: 2, FinalizedBlockHeight: big.NewInt(200), Disabled: true},
	})
	require.NoError(t, err)

	t.Run("list returns all rows including for verifier", func(t *testing.T) {
		rows, err := store.List(ctx)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(rows), 2)
		var found int
		for _, r := range rows {
			if r.VerifierID == "store-list-verifier" && (r.ChainSelector == 1 || r.ChainSelector == 2) {
				found++
				if r.ChainSelector == 1 {
					require.Equal(t, big.NewInt(100), r.FinalizedBlockHeight)
					require.False(t, r.Disabled)
				}
				if r.ChainSelector == 2 {
					require.Equal(t, big.NewInt(200), r.FinalizedBlockHeight)
					require.True(t, r.Disabled)
				}
			}
		}
		require.Equal(t, 2, found)
	})
}

func TestPostgresChainStatusStore_SetDisabled(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	ctx := t.Context()
	store := NewPostgresChainStatusStore(db, lggr)
	manager := NewPostgresChainStatusManager(store, "store-set-disabled")
	_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'store-set-disabled'")

	err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{ChainSelector: 1, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
	})
	require.NoError(t, err)

	err = store.SetDisabled(ctx, 1, "store-set-disabled", true)
	require.NoError(t, err)

	result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.True(t, result[1].Disabled)

	err = store.SetDisabled(ctx, 1, "store-set-disabled", false)
	require.NoError(t, err)
	result, err = manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
	require.NoError(t, err)
	require.False(t, result[1].Disabled)
}

func TestPostgresChainStatusStore_SetDisabled_nonexistent_returns_error(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	ctx := t.Context()
	store := NewPostgresChainStatusStore(db, lggr)

	err := store.SetDisabled(ctx, 99999, "no-such-verifier", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no row found")
}

func TestPostgresChainStatusStore_SetFinalizedBlockHeight(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	ctx := t.Context()
	store := NewPostgresChainStatusStore(db, lggr)
	manager := NewPostgresChainStatusManager(store, "store-set-height")
	_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'store-set-height'")

	err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{ChainSelector: 1, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
	})
	require.NoError(t, err)

	err = store.SetFinalizedBlockHeight(ctx, 1, "store-set-height", big.NewInt(300))
	require.NoError(t, err)

	result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, 0, big.NewInt(300).Cmp(result[1].FinalizedBlockHeight))
}

func TestPostgresChainStatusStore_SetFinalizedBlockHeight_nonexistent_returns_error(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	ctx := t.Context()
	store := NewPostgresChainStatusStore(db, lggr)

	err := store.SetFinalizedBlockHeight(ctx, 99999, "no-such-verifier", big.NewInt(1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "no row found")
}

func TestPostgresChainStatusStore_SetFinalizedBlockHeight_nil_height_returns_error(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	ctx := t.Context()
	store := NewPostgresChainStatusStore(db, lggr)

	err := store.SetFinalizedBlockHeight(ctx, 1, "v", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot be nil")
}
