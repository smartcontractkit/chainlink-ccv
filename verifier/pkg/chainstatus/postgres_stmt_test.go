package chainstatus

import (
	"context"
	"database/sql"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// captureDataSource records the statement and arguments of the last ExecContext.
// The embedded interface is nil: only ExecContext is used by WriteChainStatuses.
type captureDataSource struct {
	sqlutil.DataSource
	stmt string
	args []any
}

func (c *captureDataSource) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	c.stmt = query
	c.args = args
	return driverResult{}, nil
}

type driverResult struct{}

func (driverResult) LastInsertId() (int64, error) { return 0, nil }
func (driverResult) RowsAffected() (int64, error) { return 0, nil }

// TestWriteChainStatuses_BuildsOneStatement checks that the whole batch becomes a
// single multi-row upsert, with correct placeholder numbering and argument order.
func TestWriteChainStatuses_BuildsOneStatement(t *testing.T) {
	ds := &captureDataSource{}
	store := NewPostgresChainStatusStore(ds, logger.Test(t))

	err := store.WriteChainStatuses(t.Context(), "v1", []protocol.ChainStatusInfo{
		{ChainSelector: 10, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
		{ChainSelector: 20, FinalizedBlockHeight: big.NewInt(200), Disabled: true},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, strings.Count(ds.stmt, "INSERT INTO"), "must be one statement")
	assert.Contains(t, ds.stmt, "($1,$2,$3,$4),($5,$6,$7,$8)")
	assert.Contains(t, ds.stmt, "ON CONFLICT (chain_selector, verifier_id) DO UPDATE SET")

	require.Equal(t, []any{
		"10", "v1", "100", false,
		"20", "v1", "200", true,
	}, ds.args)
}

// TestWriteChainStatuses_DeduplicatesChain checks that a repeated chain produces one
// row. Postgres rejects an ON CONFLICT DO UPDATE that touches a row two times.
func TestWriteChainStatuses_DeduplicatesChain(t *testing.T) {
	ds := &captureDataSource{}
	store := NewPostgresChainStatusStore(ds, logger.Test(t))

	err := store.WriteChainStatuses(t.Context(), "v1", []protocol.ChainStatusInfo{
		{ChainSelector: 10, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
		{ChainSelector: 20, FinalizedBlockHeight: big.NewInt(50), Disabled: false},
		{ChainSelector: 10, FinalizedBlockHeight: big.NewInt(300), Disabled: true},
	})
	require.NoError(t, err)

	assert.Contains(t, ds.stmt, "($1,$2,$3,$4),($5,$6,$7,$8)")
	assert.NotContains(t, ds.stmt, "$9")

	// Chain 10 keeps first-seen position but the last value.
	require.Equal(t, []any{
		"10", "v1", "300", true,
		"20", "v1", "50", false,
	}, ds.args)
}

func TestWriteChainStatuses_NilHeightWritesNothing(t *testing.T) {
	ds := &captureDataSource{}
	store := NewPostgresChainStatusStore(ds, logger.Test(t))

	err := store.WriteChainStatuses(t.Context(), "v1", []protocol.ChainStatusInfo{
		{ChainSelector: 10, FinalizedBlockHeight: big.NewInt(100), Disabled: false},
		{ChainSelector: 20, FinalizedBlockHeight: nil, Disabled: false},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain 20")
	assert.Empty(t, ds.stmt, "no statement must run")
}

func TestWriteChainStatuses_EmptyIsNoop(t *testing.T) {
	ds := &captureDataSource{}
	store := NewPostgresChainStatusStore(ds, logger.Test(t))

	require.NoError(t, store.WriteChainStatuses(t.Context(), "v1", nil))
	assert.Empty(t, ds.stmt)
}
