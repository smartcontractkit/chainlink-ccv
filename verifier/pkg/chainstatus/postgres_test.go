package chainstatus

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
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

	t.Run("duplicate chain in one batch keeps the last value", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-dup-batch")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-dup-batch'")

		// One statement now upserts the whole batch. Postgres rejects an ON CONFLICT
		// DO UPDATE that touches one row two times, so duplicates must be removed.
		err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{ChainSelector: 1, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
			{ChainSelector: 2, FinalizedBlockHeight: big.NewInt(50), Disabled: false},
			{ChainSelector: 1, FinalizedBlockHeight: big.NewInt(300), Disabled: true},
		})
		require.NoError(t, err)

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1, 2})
		require.NoError(t, err)
		require.Len(t, result, 2)

		// The last value for chain 1 wins.
		assert.Equal(t, 0, big.NewInt(300).Cmp(result[1].FinalizedBlockHeight))
		assert.True(t, result[1].Disabled)
		assert.Equal(t, 0, big.NewInt(50).Cmp(result[2].FinalizedBlockHeight))
	})

	t.Run("nil block height in a batch writes nothing", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(store, "test-nil-batch")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-nil-batch'")

		err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{ChainSelector: 1, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
			{ChainSelector: 2, FinalizedBlockHeight: nil, Disabled: false},
		})
		require.Error(t, err)

		// The batch is one statement, so the valid row is not written either.
		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1, 2})
		require.NoError(t, err)
		assert.Empty(t, result)
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

func TestPostgresChainStatusStore_SetFinalizedBlockHeightWith(t *testing.T) {
	db := testutil.NewTestDB(t)
	lggr := logger.Test(t)
	store := NewPostgresChainStatusStore(db, lggr)
	const verifierID = "store-set-height-with"

	seed := func(t *testing.T) {
		t.Helper()
		_, err := db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = $1", verifierID)
		require.NoError(t, err)
		err = NewPostgresChainStatusManager(store, verifierID).WriteChainStatuses(t.Context(), []protocol.ChainStatusInfo{
			{ChainSelector: 1, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
		})
		require.NoError(t, err)
	}
	readHeight := func(t *testing.T) *big.Int {
		t.Helper()
		result, err := store.ReadChainStatuses(t.Context(), verifierID, []protocol.ChainSelector{1})
		require.NoError(t, err)
		require.Len(t, result, 1)
		return result[1].FinalizedBlockHeight
	}

	t.Run("nil callback commits the height", func(t *testing.T) {
		seed(t)
		err := store.SetFinalizedBlockHeightWith(t.Context(), 1, verifierID, big.NewInt(300), nil)
		require.NoError(t, err)
		require.Equal(t, 0, big.NewInt(300).Cmp(readHeight(t)))
	})

	t.Run("succeeding callback runs in the transaction and commits the height", func(t *testing.T) {
		seed(t)
		called := false
		err := store.SetFinalizedBlockHeightWith(t.Context(), 1, verifierID, big.NewInt(400), func(ctx context.Context, tx sqlutil.DataSource, _ *PostgresChainStatusStore) error {
			called = true
			// The callback sees the uncommitted update, which proves it runs in the same transaction.
			var h string
			if err := tx.GetContext(ctx, &h, `SELECT finalized_block_height FROM ccv_chain_statuses WHERE chain_selector = '1' AND verifier_id = $1`, verifierID); err != nil {
				return err
			}
			if h != "400" {
				return errors.New("callback did not see the updated height: " + h)
			}
			return nil
		})
		require.NoError(t, err)
		require.True(t, called)
		require.Equal(t, 0, big.NewInt(400).Cmp(readHeight(t)))
	})

	t.Run("callback error rolls back the height", func(t *testing.T) {
		seed(t)
		err := store.SetFinalizedBlockHeightWith(t.Context(), 1, verifierID, big.NewInt(500), func(context.Context, sqlutil.DataSource, *PostgresChainStatusStore) error {
			return assert.AnError
		})
		require.ErrorIs(t, err, assert.AnError)
		require.Equal(t, 0, big.NewInt(100).Cmp(readHeight(t)))
	})

	t.Run("txStore writes are part of the transaction", func(t *testing.T) {
		seed(t)
		readDisabled := func(t *testing.T) bool {
			t.Helper()
			result, err := store.ReadChainStatuses(t.Context(), verifierID, []protocol.ChainSelector{1})
			require.NoError(t, err)
			require.Len(t, result, 1)
			return result[1].Disabled
		}

		// A failing callback rolls back the txStore write along with the height.
		err := store.SetFinalizedBlockHeightWith(t.Context(), 1, verifierID, big.NewInt(600), func(ctx context.Context, _ sqlutil.DataSource, txStore *PostgresChainStatusStore) error {
			if err := txStore.SetDisabled(ctx, 1, verifierID, true); err != nil {
				return err
			}
			return assert.AnError
		})
		require.ErrorIs(t, err, assert.AnError)
		require.False(t, readDisabled(t))
		require.Equal(t, 0, big.NewInt(100).Cmp(readHeight(t)))

		// A succeeding callback commits it. Using the outer store here would wait on the transaction's row lock.
		err = store.SetFinalizedBlockHeightWith(t.Context(), 1, verifierID, big.NewInt(700), func(ctx context.Context, _ sqlutil.DataSource, txStore *PostgresChainStatusStore) error {
			return txStore.SetDisabled(ctx, 1, verifierID, true)
		})
		require.NoError(t, err)
		require.True(t, readDisabled(t))
		require.Equal(t, 0, big.NewInt(700).Cmp(readHeight(t)))
	})

	t.Run("store on a transaction is refused and changes nothing", func(t *testing.T) {
		seed(t)
		tx, err := db.BeginTxx(t.Context(), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })

		called := false
		err = NewPostgresChainStatusStore(tx, lggr).SetFinalizedBlockHeightWith(t.Context(), 1, verifierID, big.NewInt(800),
			func(context.Context, sqlutil.DataSource, *PostgresChainStatusStore) error {
				called = true
				return nil
			})
		require.ErrorIs(t, err, ErrTransactionRequired)
		require.False(t, called)
		require.NoError(t, tx.Rollback())
		require.Equal(t, 0, big.NewInt(100).Cmp(readHeight(t)))
	})

	t.Run("missing row returns error without calling callback", func(t *testing.T) {
		called := false
		err := store.SetFinalizedBlockHeightWith(t.Context(), 99999, "no-such-verifier", big.NewInt(1), func(context.Context, sqlutil.DataSource, *PostgresChainStatusStore) error {
			called = true
			return nil
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no row found")
		require.False(t, called)
	})
}
