package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	// Import postgres driver for database/sql.
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
)

// NewTestDBWithStats is NewTestDB with pg_stat_statements preloaded, for tests that
// measure how much work the database is asked to do.
//
// It is a separate constructor on purpose. NewTestDB backs every Postgres test in the
// repository, and a server that refuses to start because a contrib module is missing
// would take all of them down with it. Here a missing module reports statsAvailable
// false and the caller skips, so the blast radius is one test.
//
// pg_stat_statements counts statements, which is the unit the production check uses, so a
// ratio measured here is comparable with a ratio measured on a real database.
func NewTestDBWithStats(tb testing.TB) (dbConn *sqlx.DB, statsAvailable bool) {
	if testing.Short() {
		tb.Skip("skipping docker test in short mode")
	}
	tb.Helper()
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_verifier_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		// Append to the image's default command rather than using WithConfigFile, which
		// replaces the whole server configuration and would drop the image defaults.
		testcontainers.WithCmdArgs(
			"-c", "shared_preload_libraries=pg_stat_statements",
			"-c", "pg_stat_statements.track=all",
			"-c", "pg_stat_statements.track_utility=off",
			// Postgres 15 caches statistics for the duration of a transaction by default,
			// so two reads in one transaction would return the same numbers.
			"-c", "stats_fetch_consistency=none",
		),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				// Preloading a library slows startup, and CI runners are contended.
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		tb.Logf("postgres with pg_stat_statements did not start, load measurement unavailable: %v", err)
		return nil, false
	}

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(tb, err, "failed to get connection string")

	sqlxDB, err := sqlx.Open("postgres", connectionString)
	require.NoError(tb, err, "failed to open database")

	tb.Cleanup(func() {
		_ = sqlxDB.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			tb.Logf("failed to terminate postgres container: %v", err)
		}
	})

	require.NoError(tb, db.RunPostgresMigrations(sqlxDB), "failed to run migrations")

	if _, err := sqlxDB.ExecContext(ctx, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"); err != nil {
		tb.Logf("pg_stat_statements is not installable in this image, load measurement unavailable: %v", err)
		return sqlxDB, false
	}

	return sqlxDB, true
}
