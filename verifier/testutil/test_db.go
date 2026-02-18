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
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// NewTestDB creates a PostgreSQL testcontainer for testing with queue tables.
// It runs migrations to set up the necessary schema and returns a DataSource (*sqlx.DB).
func NewTestDB(t *testing.T) sqlutil.DataSource {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
	t.Helper()
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
		t.Fatalf("failed to start postgres container: %v", err)
	}

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	sqlxDB, err := sqlx.Open("postgres", connectionString)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Run migrations to create tables
	err = db.RunPostgresMigrations(sqlxDB)
	if err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		_ = sqlxDB.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	return sqlxDB
}

// NewTestDBWithLogger creates a PostgreSQL testcontainer for testing with logging.
func NewTestDBWithLogger(t *testing.T, lggr logger.Logger) sqlutil.DataSource {
	db := NewTestDB(t)
	lggr.Infow("Created test database")
	return db
}

// CleanupTestDB closes the database connection.
// Note: Container cleanup is handled automatically by t.Cleanup in NewTestDB.
func CleanupTestDB(t *testing.T, db sqlutil.DataSource) {
	if sqlxDB, ok := db.(*sqlx.DB); ok {
		if err := sqlxDB.Close(); err != nil {
			t.Errorf("failed to close test database: %v", err)
		}
	}
}
