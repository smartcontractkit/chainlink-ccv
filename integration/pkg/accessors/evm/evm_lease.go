package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// dbLease is what evmLease needs from dblease.Lease; tests replace it.
type dbLease interface {
	TakeAndHold(ctx context.Context, onHeld func(error)) error
	Release()
}

var errEVMDatabaseClosed = errors.New("the EVM database is closed")

// evmLease is the factory's one lease on the EVM database, shared by every accessor it hands out. The
// last holder to drop releases the lease and then closes the database, so no write lands after release.
type evmLease struct {
	lggr     logger.Logger
	db       *lazy.Lazy[*sql.DB]
	newLease func(*sql.DB) dbLease
	// gate serializes Acquire; it is a channel so a waiting Acquire still honors its ctx.
	gate chan struct{}

	mu       sync.Mutex
	held     dbLease
	closed   bool
	dbClosed bool
	holders  int
	// heldErr is why the TakeAndHold in flight is waiting; every Acquire waiting meanwhile is told it.
	heldErr    error
	waiters    map[uint64]func(error)
	nextWaiter uint64
}

func newEVMLease(lggr logger.Logger, db *lazy.Lazy[*sql.DB]) *evmLease {
	return &evmLease{
		lggr:     lggr,
		db:       db,
		newLease: func(d *sql.DB) dbLease { return evmdb.NewLease(d, lggr) },
		gate:     make(chan struct{}, 1),
		waiters:  make(map[uint64]func(error)),
	}
}

// retain registers one more holder; each must call drop once.
func (l *evmLease) retain() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.holders++
}

// drop gives up one holder's share. The last one (or any drop with no holder left) releases the lease,
// then closes the database; the lease then refuses every Acquire.
func (l *evmLease) drop() error {
	l.mu.Lock()
	if l.holders > 0 {
		l.holders--
	}
	last := l.holders == 0
	l.mu.Unlock()
	if !last {
		return nil
	}
	return l.close()
}

// Acquire returns once this process holds the lease, waiting while another process holds it. onHeld,
// when set, is called under the lease's lock, so it must not call back into the lease.
func (l *evmLease) Acquire(ctx context.Context, onHeld func(error)) error {
	unwatch := l.watchHeld(onHeld)
	defer unwatch()
	select {
	case l.gate <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("stopped waiting for the EVM database lease: %w", ctx.Err())
	}
	defer func() { <-l.gate }()

	l.mu.Lock()
	closed, held := l.closed, l.held != nil
	l.mu.Unlock()
	if closed {
		return errEVMDatabaseClosed
	}
	if held {
		return nil
	}
	db, err := l.db.Value(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect the EVM database: %w", err)
	}
	// The last drop may have run while Value connected and so not seen the pool: close it here.
	l.mu.Lock()
	closed = l.closed
	l.mu.Unlock()
	if closed {
		return errors.Join(errEVMDatabaseClosed, l.closeDB())
	}
	lease := l.newLease(db)
	err = lease.TakeAndHold(ctx, l.reportHeld)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.heldErr = nil
	if err != nil {
		return err
	}
	// The last drop ran while this Acquire waited: give the lease straight back.
	if l.closed {
		lease.Release()
		return errEVMDatabaseClosed
	}
	l.held = lease
	return nil
}

// watchHeld registers onHeld for the current wait, calling it now if a wait is already reported. The
// returned func deregisters it.
func (l *evmLease) watchHeld(onHeld func(error)) func() {
	if onHeld == nil {
		return func() {}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.nextWaiter
	l.nextWaiter++
	l.waiters[id] = onHeld
	if l.heldErr != nil {
		onHeld(l.heldErr)
	}
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.waiters, id)
	}
}

// reportHeld is the onHeld of the TakeAndHold in flight; it tells every waiting Acquire.
func (l *evmLease) reportHeld(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.heldErr = err
	for _, onHeld := range l.waiters {
		onHeld(err)
	}
}

// close releases the lease if held, then closes the database if it was connected. Later calls do nothing.
// It never waits on an Acquire in flight; that one releases its own lease when it sees close ran.
func (l *evmLease) close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	held := l.held
	l.held = nil
	l.mu.Unlock()

	if held != nil {
		held.Release()
	}
	return l.closeDB()
}

// closeDB closes the database once, if it was connected; it never connects one.
func (l *evmLease) closeDB() error {
	// Derived waits out a connect in flight, so a pool it misses is one the Acquire after it closes.
	if !l.db.Derived() {
		return nil
	}
	l.mu.Lock()
	done := l.dbClosed
	l.dbClosed = true
	l.mu.Unlock()
	if done {
		return nil
	}
	// Derived, so Value returns the open database without connecting.
	db, err := l.db.Value(context.Background())
	if err != nil || db == nil {
		return err
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close the EVM database: %w", err)
	}
	return nil
}
