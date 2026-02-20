package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
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
	if err != nil {
		tb.Fatalf("failed to start postgres container: %v", err)
	}

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		tb.Fatalf("failed to get connection string: %v", err)
	}

	sqlxDB, err := sqlx.Open("postgres", connectionString)
	if err != nil {
		tb.Fatalf("failed to open database: %v", err)
	}

	err = db.RunPostgresMigrations(sqlxDB)
	if err != nil {
		tb.Fatalf("failed to run migrations: %v", err)
	}

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
		if err := sqlxDB.Close(); err != nil {
			tb.Errorf("failed to close test database: %v", err)
		}
	}
}
