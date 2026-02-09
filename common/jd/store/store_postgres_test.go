package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	dbpkg "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(t *testing.T) *sqlx.DB {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
	t.Helper()
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_job_store_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", connectionString)
	require.NoError(t, err)

	sqlxDB := sqlx.NewDb(db, "postgres")

	err = dbpkg.RunPostgresMigrations(sqlxDB)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = sqlxDB.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	return sqlxDB
}

func TestStore_Postgres_SaveAndLoadJob(t *testing.T) {
	db := setupTestDB(t)
	store := NewPGStore(db)
	ctx := context.Background()

	// Initially no job
	_, err := store.LoadJob(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoJob)

	// Save a job
	err = store.SaveJob(ctx, "proposal-1", 1, `{"type":"ccv","config":{}}`)
	require.NoError(t, err)

	job, err := store.LoadJob(ctx)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "proposal-1", job.ProposalID)
	assert.Equal(t, int64(1), job.Version)
	assert.Equal(t, `{"type":"ccv","config":{}}`, job.Spec)
	assert.False(t, job.CreatedAt.IsZero())
	assert.False(t, job.UpdatedAt.IsZero())

	// LoadJob can be used to check presence: no ErrNoJob means a job exists
	_, err = store.LoadJob(ctx)
	require.NoError(t, err)
}

func TestStore_Postgres_SaveReplacesExistingJob(t *testing.T) {
	db := setupTestDB(t)
	store := NewPGStore(db)
	ctx := context.Background()

	err := store.SaveJob(ctx, "proposal-1", 1, `{"spec":"first"}`)
	require.NoError(t, err)

	// Save another job - should replace (only one job at a time)
	err = store.SaveJob(ctx, "proposal-2", 2, `{"spec":"second"}`)
	require.NoError(t, err)

	job, err := store.LoadJob(ctx)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "proposal-2", job.ProposalID)
	assert.Equal(t, int64(2), job.Version)
	assert.Equal(t, `{"spec":"second"}`, job.Spec)
}

func TestStore_Postgres_DeleteJob(t *testing.T) {
	db := setupTestDB(t)
	store := NewPGStore(db)
	ctx := context.Background()

	err := store.SaveJob(ctx, "proposal-1", 1, `{"spec":"job"}`)
	require.NoError(t, err)

	err = store.DeleteJob(ctx)
	require.NoError(t, err)

	_, err = store.LoadJob(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoJob)
}

func TestStore_Postgres_DeleteJob_WhenEmpty_NoError(t *testing.T) {
	db := setupTestDB(t)
	store := NewPGStore(db)
	ctx := context.Background()

	err := store.DeleteJob(ctx)
	require.NoError(t, err)
}

func TestStore_Postgres_LoadJob_ReturnsMostRecent(t *testing.T) {
	db := setupTestDB(t)
	store := NewPGStore(db)
	ctx := context.Background()

	// Save first, then replace; LoadJob returns by ORDER BY id DESC LIMIT 1
	err := store.SaveJob(ctx, "first", 1, `{"v":1}`)
	require.NoError(t, err)
	err = store.SaveJob(ctx, "second", 2, `{"v":2}`)
	require.NoError(t, err)

	job, err := store.LoadJob(ctx)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "second", job.ProposalID)
	assert.Equal(t, int64(2), job.Version)
}
