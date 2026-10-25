package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/timeutil"
)

// ErrLeaseHeld means another process holds the EVM database lease.
var ErrLeaseHeld = errors.New("lease held by another process")

// LeaseConfig is the node's LeaseLockConfig.
type LeaseConfig struct {
	DefaultQueryTimeout  time.Duration
	LeaseDuration        time.Duration
	LeaseRefreshInterval time.Duration
}

// DefaultLeaseConfig is the node's default: [Database] DefaultQueryTimeout and [Database.Lock].
func DefaultLeaseConfig() LeaseConfig {
	return LeaseConfig{DefaultQueryTimeout: 10 * time.Second, LeaseDuration: 10 * time.Second, LeaseRefreshInterval: time.Second}
}

// Lease is the node's leaseLock (core/services/pg/lease_lock.go) on database/sql, over evm.lease_lock.
// It is voluntary: it only excludes processes that also take it.
type Lease struct {
	id         uuid.UUID
	db         *sql.DB
	conn       *sql.Conn
	cfg        LeaseConfig
	lggr       logger.SugaredLogger
	stop       func()
	wgReleased sync.WaitGroup
	// exit is lggr.Fatal; tests replace it.
	exit func(msg string)
}

// NewLease is the node's NewLeaseLock, with a random client ID as the node's AppID is.
func NewLease(db *sql.DB, lggr logger.Logger, cfg LeaseConfig) *Lease {
	if cfg.LeaseRefreshInterval > cfg.LeaseDuration/2 {
		panic("refresh interval must be <= half the lease duration")
	}
	id := uuid.New()
	sl := logger.Sugared(lggr).Named("EVMDatabaseLease").With("clientID", id)
	return &Lease{id: id, db: db, cfg: cfg, lggr: sl, stop: func() {}, exit: func(msg string) { sl.Fatal(msg) }}
}

// TakeAndHold is the node's: it blocks until it holds the lease or ctx ends, then renews it until Release.
// onHeld, when set, is called once on the first attempt that does not get the lease.
func (l *Lease) TakeAndHold(ctx context.Context, onHeld func(error)) error {
	l.lggr.Debug("Taking initial lease...")
	retryCount := 0

	for {
		var gotLease bool
		var err error

		err = func() error {
			qctx, cancel := context.WithTimeout(ctx, l.cfg.DefaultQueryTimeout)
			defer cancel()
			if l.conn == nil {
				if err = l.checkoutConn(qctx); err != nil {
					return fmt.Errorf("lease lock failed to checkout initial connection: %w", err)
				}
			}
			gotLease, err = l.getLease(qctx)
			if errors.Is(err, sql.ErrConnDone) {
				l.lggr.Warnw("DB connection was unexpectedly closed; checking out a new one", "err", err)
				l.conn = nil
				return err
			}
			// As on the node, any other upsert error counts as not getting the lease and is retried.
			return nil
		}()

		if errors.Is(err, sql.ErrConnDone) {
			continue
		} else if err != nil {
			err = fmt.Errorf("failed to get the EVM database lease: %w", err)
			if l.conn != nil {
				err = errors.Join(err, l.conn.Close())
			}
			return err
		}
		if gotLease {
			break
		}
		if retryCount == 0 && onHeld != nil {
			onHeld(fmt.Errorf("EVM database %w", ErrLeaseHeld))
		}
		l.logRetry(retryCount)
		retryCount++
		select {
		case <-ctx.Done():
			err = fmt.Errorf("stopped waiting for the EVM database lease: %w", ctx.Err())
			if l.conn != nil {
				err = errors.Join(err, l.conn.Close())
			}
			return err
		case <-time.After(timeutil.JitterPct(0.1).Apply(l.cfg.LeaseRefreshInterval)):
		}
	}
	l.lggr.Debug("Got exclusive lease on database")

	lctx, cancel := context.WithCancel(context.Background())
	l.stop = cancel

	l.wgReleased.Add(1)
	// Release alone ends the lease, so the loop runs on its own context, as on the node.
	go l.loop(lctx)

	return nil
}

// Release is the node's: it releases the lease and blocks until it is released. Calling it again does nothing.
func (l *Lease) Release() {
	l.stop()
	l.wgReleased.Wait()
}

// checkoutConn is the node's: a dedicated connection, to bypass any DB contention.
func (l *Lease) checkoutConn(ctx context.Context) error {
	newConn, err := l.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed checking out connection from pool: %w", err)
	}
	l.conn = newConn
	if err = l.setInitialTimeouts(ctx); err != nil {
		return errors.Join(fmt.Errorf("failed to set initial timeouts: %w", err), l.conn.Close())
	}
	return nil
}

// setInitialTimeouts is the node's: short timeouts so a dead process cannot leave rows locked.
func (l *Lease) setInitialTimeouts(ctx context.Context) error {
	ms := l.cfg.LeaseDuration.Milliseconds()
	_, err1 := l.conn.ExecContext(ctx, fmt.Sprintf(`SET SESSION lock_timeout = %d`, ms))
	_, err2 := l.conn.ExecContext(ctx, fmt.Sprintf(`SET SESSION idle_in_transaction_session_timeout = %d`, ms))
	return errors.Join(err1, err2)
}

// logRetry is the node's schedule: powers of two, then every 1000th try.
func (l *Lease) logRetry(count int) {
	if count%1000 == 0 || (count < 1000 && count&(count-1) == 0) {
		l.lggr.Infow("Another application is currently holding the database lease (or a previous instance exited uncleanly), waiting for lease to expire...", "tryCount", count)
	}
}

// loop is the node's: renew every refresh interval, expire the lease on Release, exit if it was taken.
func (l *Lease) loop(ctx context.Context) {
	defer l.wgReleased.Done()

	refresh := time.NewTicker(l.cfg.LeaseRefreshInterval)
	defer refresh.Stop()

	for {
		select {
		case <-ctx.Done():
			qctx, cancel := context.WithTimeout(context.Background(), l.cfg.DefaultQueryTimeout)
			_, execErr := l.conn.ExecContext(qctx, `UPDATE evm.lease_lock SET expires_at=NOW() WHERE client_id = $1 AND expires_at > NOW()`, l.id)
			err := errors.Join(execErr, l.conn.Close())
			cancel()
			if err != nil {
				l.lggr.Warnw("Error trying to release lease on cancelled ctx", "err", err)
			}
			return
		case <-refresh.C:
			qctx, cancel := context.WithTimeout(ctx, l.cfg.LeaseDuration)
			gotLease, err := l.getLease(qctx)
			if errors.Is(err, sql.ErrConnDone) {
				l.lggr.Warnw("DB connection was unexpectedly closed; checking out a new one", "err", err)
				if err = l.checkoutConn(ctx); err != nil {
					l.lggr.Warnw("Error trying to refresh connection", "err", err)
				}
				gotLease, err = l.getLease(ctx)
			}
			cancel()
			if err != nil {
				l.lggr.Errorw("Error trying to refresh database lease", "err", err)
			} else if !gotLease {
				if err := l.db.Close(); err != nil {
					l.lggr.Errorw("Failed to close DB", "err", err)
				}
				l.exit("Another node has taken the lease, exiting immediately")
			}
		}
	}
}

// getLease is the node's: true when this lease holds the row, false when another holder's
// has not expired, else the error. Uses database time, as node clocks may be skewed.
func (l *Lease) getLease(ctx context.Context) (gotLease bool, err error) {
	l.lggr.Trace("Refreshing database lease")
	leaseDuration := fmt.Sprintf("%f seconds", l.cfg.LeaseDuration.Seconds())

	err = l.transactConn(ctx, func(tx *sql.Tx) error {
		// Upsert the lease_lock, only overwriting an existing one if the existing one has expired
		var res sql.Result
		res, err = tx.ExecContext(ctx, `
INSERT INTO evm.lease_lock (client_id, expires_at) VALUES ($1, NOW()+$2::interval) ON CONFLICT ((client_id IS NOT NULL)) DO UPDATE SET
client_id = EXCLUDED.client_id,
expires_at = EXCLUDED.expires_at
WHERE
evm.lease_lock.client_id = $1
OR
evm.lease_lock.expires_at < NOW()
`, l.id, leaseDuration)
		if err != nil {
			return fmt.Errorf("failed to upsert lease_lock: %w", err)
		}
		var rowsAffected int64
		rowsAffected, err = res.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get RowsAffected for lease lock upsert: %w", err)
		}
		if rowsAffected > 0 {
			gotLease = true
		}
		return nil
	})
	if err != nil {
		return gotLease, fmt.Errorf("leaseLock#GetLease failed: %w", err)
	}
	return gotLease, nil
}

// transactConn is chainlink-common's sqlutil.TransactConn on l.conn, which the node's getLease uses.
func (l *Lease) transactConn(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := l.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = tx.Rollback()
			panic(recovered)
		} else if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil &&
				!errors.Is(rbErr, sql.ErrTxDone) { // already committed or rolled back
				err = errors.Join(err, rbErr)
			}
			return
		}
		err = tx.Commit()
	}()
	err = fn(tx)
	return
}
