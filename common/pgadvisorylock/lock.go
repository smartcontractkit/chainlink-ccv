// Package pgadvisorylock holds a Postgres session-level advisory lock on a dedicated connection.
// idle_session_timeout makes the server close the session, and free the lock, if the holder stops.
package pgadvisorylock

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
	"time"
)

// releaseTimeout bounds the unlock and reset queries when a lock is released.
const releaseTimeout = 5 * time.Second

// ConnProvider gives a dedicated connection from a pool.
type ConnProvider interface {
	// Conn returns a dedicated connection. The caller must close it.
	Conn(ctx context.Context) (*sql.Conn, error)
}

var _ ConnProvider = (*sql.DB)(nil)

// Lock is a held advisory lock. Release it to give the connection back to the pool.
type Lock struct {
	conn *sql.Conn
	key  string
	once sync.Once
}

// TryAcquire takes the lock for key without waiting. It returns false, with a nil error, if a different session holds it.
// The server frees the lock when the connection sends no query for idleTimeout.
func TryAcquire(ctx context.Context, db ConnProvider, key string, idleTimeout time.Duration) (*Lock, bool, error) {
	if idleTimeout < time.Millisecond {
		return nil, false, fmt.Errorf("advisory lock %q idle timeout must be at least 1ms, got %s", key, idleTimeout)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get connection for advisory lock %q: %w", key, err)
	}
	lock := &Lock{conn: conn, key: key}

	timeoutMs := fmt.Sprintf("%d", idleTimeout.Milliseconds())
	if _, err := conn.ExecContext(ctx, `SELECT set_config('idle_session_timeout', $1, false)`, timeoutMs); err != nil {
		lock.Release()
		return nil, false, fmt.Errorf("failed to set idle_session_timeout for advisory lock %q: %w", key, err)
	}

	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&acquired); err != nil {
		lock.Release()
		return nil, false, fmt.Errorf("advisory lock %q query failed: %w", key, err)
	}
	if !acquired {
		lock.Release()
		return nil, false, nil
	}
	return lock, true, nil
}

// Heartbeat keeps the lock session active. An error means that the lock can be lost.
func (l *Lock) Heartbeat(ctx context.Context) error {
	_, err := l.conn.ExecContext(ctx, `SELECT 1`)
	return err
}

// Release unlocks and resets the session, or closes the connection if one of these steps fails.
// It is safe to call more than once and from different goroutines.
func (l *Lock) Release() {
	l.once.Do(func() {
		defer func() { _ = l.conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		if _, err := l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, l.key); err == nil {
			if _, err = l.conn.ExecContext(ctx, `RESET idle_session_timeout`); err == nil {
				return
			}
		}
		// The session state is not known, so driver.ErrBadConn makes database/sql close the connection.
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
	})
}
