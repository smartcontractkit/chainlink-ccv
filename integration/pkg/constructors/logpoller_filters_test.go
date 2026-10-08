package constructors

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

func TestMessageSentFilterRegistered(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, err := db.Exec(`
		CREATE SCHEMA IF NOT EXISTS evm;
		CREATE TABLE evm.log_poller_filters (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, evm_chain_id NUMERIC(78,0) NOT NULL);`)
	require.NoError(t, err)
	const name = "ccv-verifier - verifier-1:0x00000000000000000000000000000000000000aA"
	_, err = db.Exec(`INSERT INTO evm.log_poller_filters (name, evm_chain_id) VALUES ($1, 1)`, name)
	require.NoError(t, err)

	got, err := messageSentFilterRegistered(t.Context(), db, big.NewInt(1), name)
	require.NoError(t, err)
	require.True(t, got)

	got, err = messageSentFilterRegistered(t.Context(), db, big.NewInt(2), name)
	require.NoError(t, err)
	require.False(t, got, "a filter on another chain does not count")
}
