package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

// errDataSource is a DataSource whose every read fails, standing in for an unreachable database or
// one that was never migrated.
type errDataSource struct {
	sqlutil.DataSource
	err error
}

func (e errDataSource) GetContext(_ context.Context, _ any, _ string, _ ...any) error {
	return e.err
}

func TestNewHeadORMWithoutDataSourceIsInMemory(t *testing.T) {
	t.Parallel()

	orm, err := newHeadORM(t.Context(), big.NewInt(1337), nil, "1337")
	require.NoError(t, err)
	require.NotNil(t, orm)

	// The null ORM reports no persisted head, which is what makes the tracker rebuild from the RPC.
	head, err := orm.LatestHead(t.Context())
	require.NoError(t, err)
	require.Nil(t, head)
	require.NoError(t, orm.IdempotentInsertHead(t.Context(), nil), "writes must be discarded, not fail")
}

// TestNewHeadORMFailsFastOnUnusableDataSource covers the acceptance criterion that startup returns
// an actionable error when persisted state cannot be loaded. The tracker itself only logs a load
// failure from a background goroutine, so without this probe the process would come up healthy and
// silently unpersisted.
func TestNewHeadORMFailsFastOnUnusableDataSource(t *testing.T) {
	t.Parallel()

	ds := errDataSource{err: errors.New(`relation "evm.heads" does not exist`)}
	_, err := newHeadORM(t.Context(), big.NewInt(1337), ds, "1337")

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to read persisted EVM head state for chain 1337")
	require.ErrorContains(t, err, "evm.heads", "the error should name the missing table")
	require.ErrorContains(t, err, "migrated", "the error should tell an operator what to do")
}

func TestNewHeadORMWithDataSourceIsPersistent(t *testing.T) {
	t.Parallel()

	// A working data source: the probe read succeeds, so construction returns the persistent ORM.
	orm, err := newHeadORM(t.Context(), big.NewInt(1337), noRowsDataSource{}, "1337")
	require.NoError(t, err)
	require.IsType(t, &heads.DbORM{}, orm, "a configured data source must yield the persistent ORM")
}

// noRowsDataSource answers the startup probe the way an empty but healthy evm.heads table does.
type noRowsDataSource struct {
	sqlutil.DataSource
}

func (noRowsDataSource) GetContext(_ context.Context, _ any, _ string, _ ...any) error {
	return sql.ErrNoRows
}

func TestChainlinkConfigHeadPersistenceFollowsDataSource(t *testing.T) {
	t.Parallel()

	info := Info{
		ChainID: "1337",
		Nodes:   []Node{{HTTPUrl: "http://node.internal:8545", WSUrl: "ws://node.internal:8546"}},
	}

	withDS, err := newChainlinkEVMConfig(info, true)
	require.NoError(t, err)
	require.True(t, withDS.EVM().HeadTracker().PersistenceEnabled())

	withoutDS, err := newChainlinkEVMConfig(info, false)
	require.NoError(t, err)
	require.False(t, withoutDS.EVM().HeadTracker().PersistenceEnabled())
}

// TestChainlinkConfigWritesHeadsThrough pins the batch size. Upstream defaults to 100, which would
// leave the most recent heads unwritten when the process is killed, so persistence would look
// enabled while losing exactly the window a restart needs.
func TestChainlinkConfigWritesHeadsThrough(t *testing.T) {
	t.Parallel()

	cfg, err := newChainlinkEVMConfig(Info{
		ChainID: "1337",
		Nodes:   []Node{{HTTPUrl: "http://node.internal:8545"}},
	}, true)
	require.NoError(t, err)

	require.Equal(t, int64(1), cfg.EVM().HeadTracker().PersistenceBatchSize())
	require.Equal(t, headPersistenceBatchSize, cfg.EVM().HeadTracker().PersistenceBatchSize())
}
