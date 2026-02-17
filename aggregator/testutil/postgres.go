package testutil

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/lib/pq" // PostgreSQL driver registration
)

func SetupTestPostgresDB(t *testing.T) (*sqlx.DB, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
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
	require.NoError(t, err)

	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", connStr)
	require.NoError(t, err)

	ds := sqlx.NewDb(db, "postgres")

	cleanup := func() {
		_ = ds.Close()
		if termErr := postgresContainer.Terminate(context.Background()); termErr != nil {
			t.Logf("failed to terminate postgres container: %v", termErr)
		}
	}
	return ds, cleanup
}
