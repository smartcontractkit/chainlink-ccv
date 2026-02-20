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
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// NewTestDB creates a PostgreSQL testcontainer for testing with queue tables.
// It runs migrations to set up the necessary schema and returns a DataSource (*sqlx.DB).
// Accepts testing.TB so it works for both *testing.T and *testing.B.
func NewTestDB(tb testing.TB) sqlutil.DataSource {
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
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(tb, err, "failed to start postgres container")

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(tb, err, "failed to get connection string")

	sqlxDB, err := sqlx.Open("postgres", connectionString)
	require.NoError(tb, err, "failed to open database")

	err = db.RunPostgresMigrations(sqlxDB)
	require.NoError(tb, err, "failed to run migrations")

	tb.Cleanup(func() {
		_ = sqlxDB.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			tb.Logf("failed to terminate postgres container: %v", err)
		}
	})

	return sqlxDB
}

// CleanupTestDB closes the database connection.
// Note: Container cleanup is handled automatically by tb.Cleanup in NewTestDB.
func CleanupTestDB(tb testing.TB, dbConn sqlutil.DataSource) {
	if sqlxDB, ok := dbConn.(*sqlx.DB); ok {
		err := sqlxDB.Close()
		require.NoError(tb, err, "failed to close test database")
	}
}
