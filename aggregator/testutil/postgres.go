package testutil

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/lib/pq" // PostgreSQL driver registration
)

// SetupTestPostgresURI starts a Postgres container and returns its connection string.
func SetupTestPostgresURI(tb testing.TB) (string, func()) {
	tb.Helper()
	if testing.Short() {
		tb.Skip("skipping docker test in short mode")
	}

	ctx := context.Background()
	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_db"),
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
	cleanup := func() {
		if termErr := postgresContainer.Terminate(context.Background()); termErr != nil {
			tb.Logf("failed to terminate postgres container: %v", termErr)
		}
	}

	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		cleanup()
		tb.Fatalf("failed to get connection string: %v", err)
	}
	return connStr, cleanup
}

func SetupTestPostgresDB(tb testing.TB) (*sqlx.DB, func()) {
	tb.Helper()
	connStr, terminate := SetupTestPostgresURI(tb)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		terminate()
		tb.Fatalf("failed to open database: %v", err)
	}

	ds := sqlx.NewDb(db, "postgres")

	cleanup := func() {
		_ = ds.Close()
		terminate()
	}
	return ds, cleanup
}
