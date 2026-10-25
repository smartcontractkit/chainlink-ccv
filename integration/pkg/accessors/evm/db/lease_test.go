package db_test

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// fastLease keeps the node's ratios at test speed: renew at a tenth of the lease.
func fastLease() evmdb.LeaseConfig {
	return evmdb.LeaseConfig{DefaultQueryTimeout: 5 * time.Second, LeaseDuration: time.Second, LeaseRefreshInterval: 100 * time.Millisecond}
}

func leaseExpiresIn(t *testing.T, db *sql.DB) time.Duration {
	t.Helper()
	var secs float64
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT EXTRACT(EPOCH FROM expires_at - NOW()) FROM evm.lease_lock`).Scan(&secs))
	return time.Duration(secs * float64(time.Second))
}

func TestLeaseTakesAnEmptyTableAndReleaseExpiresIt(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	// No renewal before Release: as on the node, Release cancelling a renewal in flight breaks the
	// connection, and the lease is then left to expire.
	lease := evmdb.NewLease(db, logger.Test(t), evmdb.LeaseConfig{DefaultQueryTimeout: 5 * time.Second, LeaseDuration: time.Minute, LeaseRefreshInterval: 30 * time.Second})

	require.NoError(t, lease.TakeAndHold(t.Context(), nil))
	require.Greater(t, leaseExpiresIn(t, db), time.Duration(0), "a held lease expires in the future")

	lease.Release()
	require.LessOrEqual(t, leaseExpiresIn(t, db), time.Duration(0), "release expires the lease at once")
	lease.Release() // a second release does nothing, as on the node
}

func TestLeaseWaitsWhileHeldThenTakesOver(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	first := evmdb.NewLease(db, logger.Test(t), fastLease())
	require.NoError(t, first.TakeAndHold(t.Context(), nil))

	var held atomic.Int32
	second := evmdb.NewLease(db, logger.Test(t), fastLease())
	done := make(chan error, 1)
	go func() {
		done <- second.TakeAndHold(t.Context(), func(err error) {
			assert.ErrorIs(t, err, evmdb.ErrLeaseHeld) // assert, not require: this runs off the test goroutine
			held.Add(1)
		})
	}()

	require.Eventually(t, func() bool { return held.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Never(t, func() bool { return len(done) > 0 }, 1500*time.Millisecond, 20*time.Millisecond,
		"the second lease must wait while the first renews past its 1s lease")

	first.Release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the second lease did not take over after the first released")
	}
	require.Equal(t, int32(1), held.Load(), "onHeld fires once")
	second.Release()
}

// As on the node, losing the lease closes the whole pool and exits.
func TestLeaseLostClosesThePoolAndExits(t *testing.T) {
	testDB, url := testutil.NewTestDBWithURL(t)
	leaseDB, err := sql.Open("postgres", url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = leaseDB.Close() })

	type exit struct {
		msg     string
		pingErr error
	}
	lease := evmdb.NewLease(leaseDB, logger.Test(t), fastLease())
	exited := make(chan exit, 1)
	evmdb.SetExitForTest(lease, func(msg string) {
		// Ping here, not after exit returns, so the check proves the pool closed first.
		select {
		case exited <- exit{msg: msg, pingErr: leaseDB.PingContext(context.Background())}:
		default:
		}
	})
	require.NoError(t, lease.TakeAndHold(t.Context(), nil))
	t.Cleanup(lease.Release)

	_, err = testDB.ExecContext(t.Context(),
		`UPDATE evm.lease_lock SET client_id = gen_random_uuid(), expires_at = NOW() + interval '1 hour'`)
	require.NoError(t, err)

	select {
	case got := <-exited:
		require.Contains(t, got.msg, "exiting immediately")
		require.EqualError(t, got.pingErr, "sql: database is closed", "the pool is closed before exiting")
	case <-time.After(3 * time.Second):
		t.Fatal("losing the lease did not exit")
	}
}
