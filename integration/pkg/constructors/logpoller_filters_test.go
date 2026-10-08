package constructors

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

const (
	filtersTestChain      = protocol.ChainSelector(5009297550715157269)
	filtersTestOtherChain = protocol.ChainSelector(14767482510783485446)
)

var (
	filtersTestOnRamp      = common.HexToAddress("0x00000000000000000000000000000000000000aa")
	filtersTestOtherOnRamp = common.HexToAddress("0x00000000000000000000000000000000000000bb")
)

// newNodeTablesDB creates the minimal slice of the Chainlink node schema these lookups read.
func newNodeTablesDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db := testutil.NewTestDB(t)
	_, err := db.Exec(`
		CREATE SCHEMA IF NOT EXISTS evm;
		CREATE TABLE evm.log_poller_filters (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, evm_chain_id NUMERIC(78,0) NOT NULL);
		CREATE TABLE ccv_committee_verifier_specs (id BIGSERIAL PRIMARY KEY, committee_verifier_config TEXT NOT NULL);`)
	require.NoError(t, err)
	return db
}

func insertSpec(t *testing.T, db *sqlx.DB, verifierID string, onRamps map[protocol.ChainSelector]common.Address) {
	t.Helper()
	var cfg strings.Builder
	fmt.Fprintf(&cfg, "verifier_id = %q\n\n[on_ramp_addresses]\n", verifierID)
	for sel, addr := range onRamps {
		fmt.Fprintf(&cfg, "%q = %q\n", strconv.FormatUint(uint64(sel), 10), addr.Hex())
	}
	_, err := db.Exec(`INSERT INTO ccv_committee_verifier_specs (committee_verifier_config) VALUES ($1)`, cfg.String())
	require.NoError(t, err)
}

func TestMessageSentFilterRegistered(t *testing.T) {
	db := newNodeTablesDB(t)
	name := evm.MessageSentFilterName("verifier-1", filtersTestOnRamp)
	_, err := db.Exec(`INSERT INTO evm.log_poller_filters (name, evm_chain_id) VALUES ($1, 1)`, name)
	require.NoError(t, err)

	got, err := messageSentFilterRegistered(t.Context(), db, big.NewInt(1), name)
	require.NoError(t, err)
	require.True(t, got)

	got, err = messageSentFilterRegistered(t.Context(), db, big.NewInt(2), name)
	require.NoError(t, err)
	require.False(t, got, "a filter on another chain does not count")
}

func TestLiveMessageSentFilters(t *testing.T) {
	ctx := t.Context()

	t.Run("names every live spec's onramp on the chain", func(t *testing.T) {
		db := newNodeTablesDB(t)
		insertSpec(t, db, "verifier-1", map[protocol.ChainSelector]common.Address{
			filtersTestChain: filtersTestOnRamp, filtersTestOtherChain: filtersTestOtherOnRamp,
		})
		insertSpec(t, db, "verifier-2", map[protocol.ChainSelector]common.Address{filtersTestOtherChain: filtersTestOtherOnRamp})

		live, err := liveMessageSentFilters(ctx, db, filtersTestChain)
		require.NoError(t, err)
		require.Equal(t, map[string]struct{}{evm.MessageSentFilterName("verifier-1", filtersTestOnRamp): {}}, live)
	})

	t.Run("a spec being deleted counts as gone", func(t *testing.T) {
		db := newNodeTablesDB(t)
		insertSpec(t, db, "verifier-1", map[protocol.ChainSelector]common.Address{filtersTestChain: filtersTestOnRamp})
		tx, err := db.BeginTxx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })
		_, err = tx.ExecContext(ctx, `DELETE FROM ccv_committee_verifier_specs`)
		require.NoError(t, err)

		live, err := liveMessageSentFilters(ctx, db, filtersTestChain)
		require.NoError(t, err)
		require.Empty(t, live)
	})

	t.Run("a spec being edited stays live", func(t *testing.T) {
		db := newNodeTablesDB(t)
		insertSpec(t, db, "verifier-1", map[protocol.ChainSelector]common.Address{filtersTestChain: filtersTestOnRamp})
		tx, err := db.BeginTxx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })
		_, err = tx.ExecContext(ctx, `UPDATE ccv_committee_verifier_specs SET committee_verifier_config = committee_verifier_config || ' '`)
		require.NoError(t, err)

		live, err := liveMessageSentFilters(ctx, db, filtersTestChain)
		require.NoError(t, err)
		require.Len(t, live, 1)
	})

	t.Run("an unparsable spec fails the lookup", func(t *testing.T) {
		db := newNodeTablesDB(t)
		_, err := db.Exec(`INSERT INTO ccv_committee_verifier_specs (committee_verifier_config) VALUES ('not = [toml')`)
		require.NoError(t, err)

		_, err = liveMessageSentFilters(ctx, db, filtersTestChain)
		require.ErrorContains(t, err, "failed to parse committee verifier spec")
	})
}
