package db_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jmoiron/sqlx"
	"github.com/scylladb/go-reflectx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/db"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

// headBatchSize matches the accessor's write-through setting so heads land in the table
// immediately. chainlink-evm's ORM buffers inserts until this many heads are queued.
const headBatchSize = 1

var testChainID = big.NewInt(1337)

// newEVMTestDB starts postgres, runs the bootstrap migrations, and returns a handle mapped the way
// chain accessors receive it (see bootstrap.accessorDataSource). The snake_case mapper is not
// optional: chainlink-evm's row structs carry no db tags, so the default sqlx mapper resolves
// Head.L1BlockNumber to "l1blocknumber" and every query below fails.
func newEVMTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("evm_heads_test_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	dbURL, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	conn, err := sqlx.ConnectContext(ctx, "postgres", dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, db.RunMigrations(conn))

	mapped := sqlx.NewDb(conn.DB, conn.DriverName())
	mapped.MapperFunc(reflectx.CamelToSnakeASCII)
	return mapped
}

func newHead(number int64, hash, parent common.Hash) *evmtypes.Head {
	head := evmtypes.NewHead(big.NewInt(number), hash, parent, sqlutil.New(testChainID))
	return &head
}

func hashOf(b byte) common.Hash {
	return common.BytesToHash([]byte{b})
}

// TestMigrationsCreateEVMHeads checks the schema the accessor depends on exists after migrating.
func TestMigrationsCreateEVMHeads(t *testing.T) {
	conn := newEVMTestDB(t)
	ctx := t.Context()

	var count int
	require.NoError(t, conn.GetContext(ctx, &count,
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'evm' AND table_name = 'heads'"))
	require.Equal(t, 1, count, "evm.heads should exist after migrations")

	// The ORM's ON CONFLICT DO NOTHING insert is only idempotent if this index is present.
	require.NoError(t, conn.GetContext(ctx, &count,
		"SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'evm' AND indexname = 'idx_heads_evm_chain_id_hash'"))
	require.Equal(t, 1, count, "unique index on (evm_chain_id, hash) should exist")
}

// TestMigrationsAreRepeatable covers the acceptance criterion that migrations are safe to run more
// than once, which is what happens on every process start.
func TestMigrationsAreRepeatable(t *testing.T) {
	conn := newEVMTestDB(t)

	// newEVMTestDB already migrated once; running again must be a no-op rather than an error.
	require.NoError(t, db.RunMigrations(conn))
	require.NoError(t, db.RunMigrations(conn))

	var count int
	require.NoError(t, conn.GetContext(t.Context(), &count,
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'evm' AND table_name = 'heads'"))
	require.Equal(t, 1, count)
}

// TestHeadORMRoundTrip exercises the queries chainlink-evm runs against this schema. It is the
// check that the copied column names, types, and constraints actually match the ORM, which a
// schema-shape assertion alone would not catch.
func TestHeadORMRoundTrip(t *testing.T) {
	conn := newEVMTestDB(t)
	ctx := t.Context()
	orm := heads.NewORM(*testChainID, conn, headBatchSize)

	require.NoError(t, orm.IdempotentInsertHead(ctx, newHead(1, hashOf(1), hashOf(0))))
	require.NoError(t, orm.IdempotentInsertHead(ctx, newHead(2, hashOf(2), hashOf(1))))

	latest, err := orm.LatestHead(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)
	require.Equal(t, int64(2), latest.BlockNumber())

	byHash, err := orm.HeadByHash(ctx, hashOf(1))
	require.NoError(t, err)
	require.NotNil(t, byHash)
	require.Equal(t, int64(1), byHash.BlockNumber())

	all, err := orm.LatestHeads(ctx, 0)
	require.NoError(t, err)
	require.Len(t, all, 2)
}

// TestHeadORMInsertIsIdempotent covers re-inserting a head the tracker has already saved, which
// happens when a restart replays heads a previous run persisted.
func TestHeadORMInsertIsIdempotent(t *testing.T) {
	conn := newEVMTestDB(t)
	ctx := t.Context()
	orm := heads.NewORM(*testChainID, conn, headBatchSize)

	for range 3 {
		require.NoError(t, orm.IdempotentInsertHead(ctx, newHead(1, hashOf(1), hashOf(0))))
	}

	all, err := orm.LatestHeads(ctx, 0)
	require.NoError(t, err)
	require.Len(t, all, 1, "the same head must not produce duplicate rows")
}

// TestHeadStateSurvivesRestart is the restart-recovery case: heads written by one ORM instance are
// readable by a fresh one over the same database, which is what a new process gets on startup.
func TestHeadStateSurvivesRestart(t *testing.T) {
	conn := newEVMTestDB(t)
	ctx := t.Context()

	before := heads.NewORM(*testChainID, conn, headBatchSize)
	for i := int64(1); i <= 5; i++ {
		require.NoError(t, before.IdempotentInsertHead(ctx, newHead(i, hashOf(byte(i)), hashOf(byte(i-1)))))
	}

	// A new ORM stands in for the process restarting: no in-memory state carries over.
	after := heads.NewORM(*testChainID, conn, headBatchSize)

	latest, err := after.LatestHead(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest, "a restarted process must find the persisted head")
	require.Equal(t, int64(5), latest.BlockNumber())

	// heads.Saver.Load reads back this way, from the oldest head worth keeping.
	recovered, err := after.LatestHeads(ctx, 3)
	require.NoError(t, err)
	require.Len(t, recovered, 3, "heads at or above the minimum block should be recovered")
	require.Equal(t, int64(5), recovered[0].BlockNumber())
}

// TestHeadORMTrimsOldHeads covers the retention policy: heads below the finalized block minus
// HistoryDepth are deleted, so the table does not grow without bound.
func TestHeadORMTrimsOldHeads(t *testing.T) {
	conn := newEVMTestDB(t)
	ctx := t.Context()
	orm := heads.NewORM(*testChainID, conn, headBatchSize)

	for i := int64(1); i <= 10; i++ {
		require.NoError(t, orm.IdempotentInsertHead(ctx, newHead(i, hashOf(byte(i)), hashOf(byte(i-1)))))
	}

	// The first call only records a baseline: the ORM trims once the minimum block has advanced
	// more than one batch past the last trim, so with write-through batching it acts on the second
	// call and then on every other block after that.
	require.NoError(t, orm.TrimOldHeads(ctx, 7))
	require.NoError(t, orm.TrimOldHeads(ctx, 9))

	remaining, err := orm.LatestHeads(ctx, 0)
	require.NoError(t, err)
	require.Len(t, remaining, 2, "heads below the minimum block should be trimmed")
}

// TestHeadORMIsScopedToChain guards the multi-chain case: one accessor per chain shares this table,
// so a query must never return another chain's heads.
func TestHeadORMIsScopedToChain(t *testing.T) {
	conn := newEVMTestDB(t)
	ctx := t.Context()

	otherChainID := big.NewInt(31337)
	thisChain := heads.NewORM(*testChainID, conn, headBatchSize)
	otherChain := heads.NewORM(*otherChainID, conn, headBatchSize)

	require.NoError(t, thisChain.IdempotentInsertHead(ctx, newHead(1, hashOf(1), hashOf(0))))

	otherHead := evmtypes.NewHead(big.NewInt(99), hashOf(99), hashOf(98), sqlutil.New(otherChainID))
	require.NoError(t, otherChain.IdempotentInsertHead(ctx, &otherHead))

	latest, err := thisChain.LatestHead(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)
	require.Equal(t, int64(1), latest.BlockNumber(), "must not see the other chain's higher head")
}
