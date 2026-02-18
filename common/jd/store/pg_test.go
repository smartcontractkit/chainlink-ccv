package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	_ "github.com/lib/pq"
)

// jobStoreTableDDL is the schema expected by PostgresStore (must match pg.go comment).
const jobStoreTableDDL = `
CREATE TABLE IF NOT EXISTS job_store (
	id SERIAL PRIMARY KEY,
	proposal_id TEXT NOT NULL,
	version BIGINT NOT NULL,
	spec TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`

var (
	testPGConnStr string
	testPGCleanup func()
)

func TestMain(m *testing.M) {
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-test.short" || strings.HasPrefix(os.Args[i], "-test.short=") {
			os.Exit(m.Run())
			return
		}
	}
	ctx := context.Background()
	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("jd_store_test_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		_, _ = os.Stderr.WriteString("failed to start postgres container: " + err.Error() + "\n")
		os.Exit(1)
	}
	testPGConnStr, err = postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = postgresContainer.Terminate(context.Background())
		_, _ = os.Stderr.WriteString("failed to get connection string: " + err.Error() + "\n")
		os.Exit(1)
	}
	db, err := sql.Open("postgres", testPGConnStr)
	if err != nil {
		_ = postgresContainer.Terminate(context.Background())
		_, _ = os.Stderr.WriteString("failed to connect to postgres: " + err.Error() + "\n")
		os.Exit(1)
	}
	if _, err := db.ExecContext(ctx, jobStoreTableDDL); err != nil {
		_ = db.Close()
		_ = postgresContainer.Terminate(context.Background())
		_, _ = os.Stderr.WriteString("failed to create job_store table: " + err.Error() + "\n")
		os.Exit(1)
	}
	_ = db.Close()
	testPGCleanup = func() {
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			_, _ = os.Stderr.WriteString("failed to terminate postgres container: " + err.Error() + "\n")
		}
	}
	code := m.Run()
	testPGCleanup()
	os.Exit(code)
}

// setupPostgresStore connects to the shared test DB (started in TestMain), clears job_store, and returns
// a PostgresStore plus cleanup. Skips when testing.Short() is set.
func setupPostgresStore(t *testing.T) (*PostgresStore, sqlutil.DataSource, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
	if testPGConnStr == "" {
		t.Fatal("test DB URL not set (TestMain may have failed)")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", testPGConnStr)
	require.NoError(t, err)
	ds := sqlx.NewDb(db, "postgres")
	_, err = ds.ExecContext(ctx, `DELETE FROM job_store`)
	require.NoError(t, err, "clear job_store for test isolation")
	store := NewPostgresStore(ds)
	cleanup := func() { _ = ds.Close() }
	return store, ds, cleanup
}

func TestPostgresStore_SaveAndLoadJob(t *testing.T) {
	s, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	_, err := s.LoadJob(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoJob)

	err = s.SaveJob(ctx, "proposal-1", 1, `{"type":"ccv"}`)
	require.NoError(t, err)

	job, err := s.LoadJob(ctx)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "proposal-1", job.ProposalID)
	assert.Equal(t, int64(1), job.Version)
	assert.Equal(t, `{"type":"ccv"}`, job.Spec)
}

func TestPostgresStore_SaveReplacesExistingJob(t *testing.T) {
	s, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, s.SaveJob(ctx, "proposal-1", 1, `{"v":1}`))
	require.NoError(t, s.SaveJob(ctx, "proposal-2", 2, `{"v":2}`))

	job, err := s.LoadJob(ctx)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "proposal-2", job.ProposalID)
	assert.Equal(t, int64(2), job.Version)
	assert.Equal(t, `{"v":2}`, job.Spec)
}

func TestPostgresStore_HasJob(t *testing.T) {
	s, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	has, err := s.HasJob(ctx)
	require.NoError(t, err)
	assert.False(t, has)

	require.NoError(t, s.SaveJob(ctx, "p1", 1, "spec"))
	has, err = s.HasJob(ctx)
	require.NoError(t, err)
	assert.True(t, has)

	require.NoError(t, s.DeleteJob(ctx))
	has, err = s.HasJob(ctx)
	require.NoError(t, err)
	assert.False(t, has)
}

func TestPostgresStore_DeleteJob(t *testing.T) {
	s, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, s.SaveJob(ctx, "proposal-1", 1, `{}`))
	require.NoError(t, s.DeleteJob(ctx))

	_, err := s.LoadJob(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoJob)

	require.NoError(t, s.DeleteJob(ctx))
}

func TestPostgresStore_DeleteJob_WhenEmpty(t *testing.T) {
	s, _, cleanup := setupPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, s.DeleteJob(ctx))
}

func TestPostgresStore_NewPostgresStore(t *testing.T) {
	_, ds, cleanup := setupPostgresStore(t)
	defer cleanup()

	store := NewPostgresStore(ds)
	require.NotNil(t, store)
}
