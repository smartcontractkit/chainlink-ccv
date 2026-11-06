package pgadvisorylock_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/common/pgadvisorylock"
)

const key = "pgadvisorylock_test"

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:15-alpine",
		postgres.WithDatabase("lock_test_db"), postgres.WithUsername("test_user"), postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(30*time.Second)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	db, err := sql.Open("postgres", url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func tryLock(t *testing.T, db *sql.DB, idleTimeout time.Duration) (*pgadvisorylock.Lock, bool) {
	t.Helper()
	lock, acquired, err := pgadvisorylock.TryAcquire(t.Context(), db, key, idleTimeout)
	require.NoError(t, err)
	return lock, acquired
}

func TestTryAcquire(t *testing.T) {
	db := newTestDB(t)

	t.Run("second caller does not get the lock until the first releases it", func(t *testing.T) {
		lock, ok := tryLock(t, db, time.Minute)
		require.True(t, ok)
		_, ok = tryLock(t, db, time.Minute)
		require.False(t, ok)

		lock.Release()
		lock.Release() // safe to call more than once

		lock, ok = tryLock(t, db, time.Minute)
		require.True(t, ok)
		lock.Release()
	})

	t.Run("different keys do not block each other", func(t *testing.T) {
		lock, ok := tryLock(t, db, time.Minute)
		require.True(t, ok)
		defer lock.Release()
		other, ok, err := pgadvisorylock.TryAcquire(t.Context(), db, key+"_other", time.Minute)
		require.NoError(t, err)
		require.True(t, ok)
		other.Release()
	})

	t.Run("database frees the lock when no heartbeat comes within the idle timeout", func(t *testing.T) {
		lock, ok := tryLock(t, db, time.Second)
		require.True(t, ok)

		require.Eventually(t, func() bool {
			l, ok, err := pgadvisorylock.TryAcquire(t.Context(), db, key, time.Minute)
			if err != nil || !ok {
				return false
			}
			l.Release()
			return true
		}, 5*time.Second, 100*time.Millisecond)

		require.Error(t, lock.Heartbeat(t.Context()), "heartbeat on a closed session must fail")
		lock.Release()
	})

	t.Run("heartbeat keeps the lock past the idle timeout", func(t *testing.T) {
		lock, ok := tryLock(t, db, time.Second)
		require.True(t, ok)
		defer lock.Release()

		for range 6 {
			time.Sleep(300 * time.Millisecond)
			require.NoError(t, lock.Heartbeat(t.Context()))
		}
		_, ok = tryLock(t, db, time.Minute)
		require.False(t, ok, "lock must still be held after 1.8s with heartbeats")
	})

	t.Run("released connection goes back to the pool with idle_session_timeout reset", func(t *testing.T) {
		db.SetMaxOpenConns(1)
		defer db.SetMaxOpenConns(0)

		lock, ok := tryLock(t, db, time.Second)
		require.True(t, ok)
		lock.Release()

		time.Sleep(1500 * time.Millisecond)
		var timeout string
		require.NoError(t, db.QueryRowContext(t.Context(), "SHOW idle_session_timeout").Scan(&timeout))
		require.Equal(t, "0", timeout)
	})

	t.Run("rejects an idle timeout below 1ms", func(t *testing.T) {
		_, _, err := pgadvisorylock.TryAcquire(t.Context(), db, key, 0)
		require.Error(t, err)
	})
}
