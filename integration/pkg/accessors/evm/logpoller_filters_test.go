package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

var filterTestOnRamp = common.HexToAddress("0x00000000000000000000000000000000000000a1")

func TestVerifierFilterPrefixMatchesFilterName(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"v", "v_1", "v%", "v:x", `v\`, "committee-verifier-1", "ü"} {
		name := logpoller.FilterName("ccv-verifier", id, filterTestOnRamp.Hex())
		assert.Equal(t, name, verifierFilterName(id, filterTestOnRamp), "ID %q", id)
		assert.True(t, len(name) > len(verifierFilterPrefix(id)), "ID %q", id)
		assert.Equal(t, name[:len(verifierFilterPrefix(id))], verifierFilterPrefix(id), "ID %q", id)
		assert.True(t, isVerifierFilterName(name, id), "ID %q", id)
	}
}

func TestIsVerifierFilterName(t *testing.T) {
	t.Parallel()
	own := verifierFilterName("v", filterTestOnRamp)
	other := verifierFilterName("v:x", filterTestOnRamp)

	assert.True(t, isVerifierFilterName(own, "v"))
	assert.False(t, isVerifierFilterName(other, "v"), "v:x's filter has v's prefix but not its shape")
	assert.True(t, isVerifierFilterName(other, "v:x"))
	assert.False(t, isVerifierFilterName(verifierFilterName("other", filterTestOnRamp), "v"))
	assert.False(t, isVerifierFilterName("ccv-verifier - v:", "v"), "no on-ramp suffix")
	assert.False(t, isVerifierFilterName("ccv-verifier - v:0xnothex000000000000000000000000000000000000", "v"))
	assert.False(t, isVerifierFilterName("legacy filter", "v"))
}

func TestCleanVerifierFilters(t *testing.T) {
	t.Run("only the verifier's filters on the ORM's chain are removed", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB
		handle := evmdb.NewLogPollerDB(db)
		ctx := context.Background()
		const chainID, otherChainID = 910_301, 910_302
		orm := logpoller.NewORM(big.NewInt(chainID), handle, logger.Test(t))
		otherORM := logpoller.NewORM(big.NewInt(otherChainID), handle, logger.Test(t))

		insert := func(o *logpoller.DSORM, name string, addr common.Address) {
			require.NoError(t, o.InsertFilter(ctx, logpoller.Filter{
				Name:      name,
				Addresses: evmtypes.AddressArray{addr},
				EventSigs: evmtypes.HashArray{common.HexToHash("0x01")},
			}))
		}
		otherOnRamp := common.HexToAddress("0xbeef")
		ids := []string{"v_1", "v%", "v:x", `v\`, "other", "v1", "vX1"}
		for _, id := range ids {
			insert(orm, verifierFilterName(id, filterTestOnRamp), filterTestOnRamp)
		}
		insert(orm, verifierFilterName("v", filterTestOnRamp), filterTestOnRamp)
		insert(orm, verifierFilterName("v", otherOnRamp), otherOnRamp)
		insert(orm, "legacy filter", filterTestOnRamp)
		insert(otherORM, verifierFilterName("v", filterTestOnRamp), filterTestOnRamp)

		require.NoError(t, cleanVerifierFilters(ctx, orm, "v"))

		stored, err := orm.LoadFilters(ctx)
		require.NoError(t, err)
		want := make([]string, 0, 1+len(ids))
		want = append(want, "legacy filter")
		for _, id := range ids {
			want = append(want, verifierFilterName(id, filterTestOnRamp))
		}
		got := make([]string, 0, len(stored))
		for name := range stored {
			got = append(got, name)
		}
		assert.ElementsMatch(t, want, got, "every other verifier's filter, including v:x's, and the legacy one stay")

		otherStored, err := otherORM.LoadFilters(ctx)
		require.NoError(t, err)
		assert.Contains(t, otherStored, verifierFilterName("v", filterTestOnRamp), "another chain's filter stays")
	})

	t.Run("logs and blocks are untouched and an empty table is fine", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB
		ctx := context.Background()
		orm := logpoller.NewORM(big.NewInt(910_303), evmdb.NewLogPollerDB(db), logger.Test(t))
		require.NoError(t, cleanVerifierFilters(ctx, orm, "v"))

		require.NoError(t, orm.InsertFilter(ctx, logpoller.Filter{
			Name:      verifierFilterName("v", filterTestOnRamp),
			Addresses: evmtypes.AddressArray{filterTestOnRamp},
			EventSigs: evmtypes.HashArray{common.HexToHash("0x01")},
		}))
		_, err := db.ExecContext(ctx, `INSERT INTO evm.log_poller_blocks
			(evm_chain_id, block_hash, block_number, block_timestamp, finalized_block_number, created_at)
			VALUES (910303, $1, 10, now(), 5, now())`, common.Hash{9}.Bytes())
		require.NoError(t, err)

		require.NoError(t, cleanVerifierFilters(ctx, orm, "v"))
		var blocks int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM evm.log_poller_blocks`).Scan(&blocks))
		assert.Equal(t, 1, blocks)
	})

	t.Run("a database without the evm schema returns an error", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB
		_, err := db.ExecContext(context.Background(), `DROP SCHEMA evm CASCADE`)
		require.NoError(t, err)
		orm := logpoller.NewORM(big.NewInt(910_304), evmdb.NewLogPollerDB(db), logger.Test(t))
		require.Error(t, cleanVerifierFilters(context.Background(), orm, "v"))
	})

	t.Run("a load failure and delete failures are returned", func(t *testing.T) {
		rec := &staleFilterRecorder{}
		loadFail := &storedFiltersORM{rec: rec, loadErr: errors.New("db down")}
		require.ErrorContains(t, cleanVerifierFilters(context.Background(), loadFail, "v"), "db down")

		name := verifierFilterName("v", filterTestOnRamp)
		deleteFail := &storedFiltersORM{rec: rec, filters: map[string]logpoller.Filter{name: {}}, deleteErr: errors.New("locked")}
		require.ErrorContains(t, cleanVerifierFilters(context.Background(), deleteFail, "v"), "locked")
	})

	t.Run("a done context stops the deletes and reports the filters left", func(t *testing.T) {
		rec := &staleFilterRecorder{}
		name := verifierFilterName("v", filterTestOnRamp)
		orm := &storedFiltersORM{rec: rec, filters: map[string]logpoller.Filter{name: {}}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := cleanVerifierFilters(ctx, orm, "v")
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorContains(t, err, name)
		assert.Equal(t, []string{"load"}, rec.snapshot())
	})
}

func TestFactoryCleansUnusedFiltersOncePerProcess(t *testing.T) {
	const chainID, otherChainID, unconfiguredChainID = 910_401, 910_402, 910_403
	// setup returns a LogPoller-off factory for verifier "v" on chainID and otherChainID. Its database
	// holds filters of "v" on all three chains and of verifier "other" on chainID.
	setup := func(t *testing.T) (*factory, *sql.DB) {
		db := testutil.NewTestDB(t).DB
		insertTestFilter(t, db, chainID, "v")
		insertTestFilter(t, db, otherChainID, "v")
		insertTestFilter(t, db, unconfiguredChainID, "v")
		insertTestFilter(t, db, chainID, "other")
		f := newSourceFactory(t, &lpStubRuntime{stubChainRuntime: newStubRuntime(t), chainID: big.NewInt(chainID)}).(*factory)
		f.db = staticDatabase(db)
		f.verifierID = "v"
		f.chainIDs = []*big.Int{big.NewInt(chainID), big.NewInt(otherChainID)}
		return f, db
	}

	t.Run("the first RPC reader removes the verifier's filters on every configured chain", func(t *testing.T) {
		f, db := setup(t)
		acc, err := f.GetAccessor(t.Context(), testSourceSelector)
		require.NoError(t, err)
		_, err = acc.SourceReader()
		require.NoError(t, err)

		assert.Zero(t, countTestFilters(t, db, chainID, "v"))
		assert.Zero(t, countTestFilters(t, db, otherChainID, "v"))
		assert.Equal(t, 1, countTestFilters(t, db, chainID, "other"), "another verifier's filter must stay")
		assert.Equal(t, 1, countTestFilters(t, db, unconfiguredChainID, "v"), "only configured chains are cleaned")
	})

	t.Run("it runs once per process", func(t *testing.T) {
		f, db := setup(t)
		f.cleanUnusedFilters()
		insertTestFilter(t, db, chainID, "v")
		f.cleanUnusedFilters()
		assert.Equal(t, 1, countTestFilters(t, db, chainID, "v"))
	})

	t.Run("with the LogPoller on nothing is removed", func(t *testing.T) {
		f, db := setup(t)
		f.logPollerEnabled = true
		f.cleanUnusedFilters()
		assert.Equal(t, 1, countTestFilters(t, db, chainID, "v"))
	})

	t.Run("without a verifier ID nothing is removed", func(t *testing.T) {
		f, db := setup(t)
		f.verifierID = ""
		f.cleanUnusedFilters()
		assert.Equal(t, 1, countTestFilters(t, db, chainID, "v"))
	})
}

func insertTestFilter(t *testing.T, db *sql.DB, chainID int64, verifierID string) {
	t.Helper()
	orm := logpoller.NewORM(big.NewInt(chainID), evmdb.NewLogPollerDB(db), logger.Test(t))
	require.NoError(t, orm.InsertFilter(t.Context(), logpoller.Filter{
		Name:      verifierFilterName(verifierID, filterTestOnRamp),
		Addresses: evmtypes.AddressArray{filterTestOnRamp},
		EventSigs: evmtypes.HashArray{common.HexToHash("0x01")},
	}))
}

func countTestFilters(t *testing.T, db *sql.DB, chainID int64, verifierID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM evm.log_poller_filters WHERE evm_chain_id = $1 AND name = $2`,
		chainID, verifierFilterName(verifierID, filterTestOnRamp)).Scan(&n))
	return n
}

// The standalone LogPoller reader does its own stale-filter cleanup through the ORM, so the accessor
// must hand it one for its chain.
func TestAccessorLogPollerReaderGetsAnORM(t *testing.T) {
	runtime := &lpStubRuntime{stubChainRuntime: newStubRuntime(t), lp: lpmocks.NewLogPoller(t), chainID: big.NewInt(910_501)}
	acc := newLogPollerAccessor(t, runtime)
	acc.db = staticDatabase(testutil.NewTestDB(t).DB)

	reader, err := acc.SourceReader()
	require.NoError(t, err)
	require.NotNil(t, reader.(*LogPollerSourceReader).cfg.ORM)
}

func TestStaleVerifierFilters(t *testing.T) {
	t.Parallel()
	own := verifierFilterName("v", filterTestOnRamp)
	old := verifierFilterName("v", common.HexToAddress("0xabcd"))
	older := verifierFilterName("v", common.HexToAddress("0x0abc"))
	orm := &storedFiltersORM{rec: &staleFilterRecorder{}, filters: map[string]logpoller.Filter{
		own:   {},
		old:   {},
		older: {},
		verifierFilterName("v:x", filterTestOnRamp):   {},
		verifierFilterName("other", filterTestOnRamp): {},
		"legacy filter": {},
	}}

	got, err := staleVerifierFilters(t.Context(), orm, "v", own)
	require.NoError(t, err)
	assert.Equal(t, []string{older, old}, got, "own name, other verifiers and other shapes are left out, in name order")

	got, err = staleVerifierFilters(t.Context(), orm, "v", "")
	require.NoError(t, err)
	assert.Len(t, got, 3)

	orm.loadErr = errors.New("db down")
	_, err = staleVerifierFilters(t.Context(), orm, "v", "")
	require.ErrorContains(t, err, "db down")
}
