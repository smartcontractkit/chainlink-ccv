package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
)

// discoveryLockKey is the name of the advisory lock that allows one discovery leader across all replicas.
const discoveryLockKey = "indexer_discovery"

// leaseReleaseTimeout bounds the unlock and reset queries when a lease is released.
const leaseReleaseTimeout = 5 * time.Second

var _ common.DiscoveryLocker = (*PostgresStorage)(nil)

// TryAcquireDiscoveryLock holds a session-level advisory lock on a dedicated connection.
// idle_session_timeout makes the server close the session, and free the lock, if no heartbeat comes.
func (d *PostgresStorage) TryAcquireDiscoveryLock(ctx context.Context, leaseTimeout time.Duration) (common.DiscoveryLease, bool, error) {
	if leaseTimeout < time.Millisecond {
		return nil, false, fmt.Errorf("discovery lease timeout must be at least 1ms, got %s", leaseTimeout)
	}

	conn, err := d.ds.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get connection for discovery lock: %w", err)
	}
	lease := &discoveryLease{conn: conn}

	timeoutMs := fmt.Sprintf("%d", leaseTimeout.Milliseconds())
	if _, err := conn.ExecContext(ctx, `SELECT set_config('idle_session_timeout', $1, false)`, timeoutMs); err != nil {
		lease.Release()
		return nil, false, fmt.Errorf("failed to set idle_session_timeout for discovery lock: %w", err)
	}

	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, discoveryLockKey).Scan(&acquired); err != nil {
		lease.Release()
		return nil, false, fmt.Errorf("discovery lock query failed: %w", err)
	}
	if !acquired {
		lease.Release()
		return nil, false, nil
	}
	return lease, true, nil
}

type discoveryLease struct {
	conn *sql.Conn
	once sync.Once
}

// Heartbeat keeps the lock session active. An error means that the lock can be lost.
func (l *discoveryLease) Heartbeat(ctx context.Context) error {
	_, err := l.conn.ExecContext(ctx, `SELECT 1`)
	return err
}

// Release unlocks and resets the session, or closes the connection if one of these steps fails.
func (l *discoveryLease) Release() {
	l.once.Do(func() {
		defer func() { _ = l.conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), leaseReleaseTimeout)
		defer cancel()
		if _, err := l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, discoveryLockKey); err == nil {
			if _, err = l.conn.ExecContext(ctx, `RESET idle_session_timeout`); err == nil {
				return
			}
		}
		// The session state is not known, so driver.ErrBadConn makes database/sql close the connection.
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
	})
}
