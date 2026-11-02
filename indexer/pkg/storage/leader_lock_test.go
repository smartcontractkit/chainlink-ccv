package storage

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/testutil"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func newTestPostgresStorage(t *testing.T) (*PostgresStorage, *sqlx.DB) {
	t.Helper()
	db, cleanup := testutil.SetupTestPostgresDB(t)
	t.Cleanup(cleanup)
	require.NoError(t, RunMigrationsContext(t.Context(), db))
	return &PostgresStorage{ds: db, lggr: logger.Test(t), monitoring: monitoring.NewNoopIndexerMonitoring()}, db
}

func tryLock(t *testing.T, s *PostgresStorage, leaseTimeout time.Duration) (common.DiscoveryLease, bool) {
	t.Helper()
	lease, acquired, err := s.TryAcquireDiscoveryLock(t.Context(), leaseTimeout)
	require.NoError(t, err)
	return lease, acquired
}

func TestTryAcquireDiscoveryLock(t *testing.T) {
	s, db := newTestPostgresStorage(t)

	t.Run("second caller does not get the lock until the first releases it", func(t *testing.T) {
		lease, ok := tryLock(t, s, time.Minute)
		require.True(t, ok)
		_, ok = tryLock(t, s, time.Minute)
		require.False(t, ok)

		lease.Release()
		lease.Release() // safe to call more than once

		lease, ok = tryLock(t, s, time.Minute)
		require.True(t, ok)
		lease.Release()
	})

	t.Run("database frees the lock when no heartbeat comes within the lease timeout", func(t *testing.T) {
		lease, ok := tryLock(t, s, time.Second)
		require.True(t, ok)

		require.Eventually(t, func() bool {
			l, ok, err := s.TryAcquireDiscoveryLock(t.Context(), time.Minute)
			if err != nil || !ok {
				return false
			}
			l.Release()
			return true
		}, 5*time.Second, 100*time.Millisecond)

		require.Error(t, lease.Heartbeat(t.Context()), "heartbeat on a closed session must fail")
		lease.Release()
	})

	t.Run("heartbeat keeps the lock past the lease timeout", func(t *testing.T) {
		lease, ok := tryLock(t, s, time.Second)
		require.True(t, ok)
		defer lease.Release()

		for range 6 {
			time.Sleep(300 * time.Millisecond)
			require.NoError(t, lease.Heartbeat(t.Context()))
		}
		_, ok = tryLock(t, s, time.Minute)
		require.False(t, ok, "lock must still be held after 1.8s with heartbeats")
	})

	t.Run("released connection goes back to the pool with idle_session_timeout reset", func(t *testing.T) {
		db.SetMaxOpenConns(1)
		defer db.SetMaxOpenConns(0)

		lease, ok := tryLock(t, s, time.Second)
		require.True(t, ok)
		lease.Release()

		time.Sleep(1500 * time.Millisecond)
		var timeout string
		require.NoError(t, db.GetContext(t.Context(), &timeout, "SHOW idle_session_timeout"))
		require.Equal(t, "0", timeout)
	})

	t.Run("rejects a lease timeout below 1ms", func(t *testing.T) {
		_, _, err := s.TryAcquireDiscoveryLock(t.Context(), 0)
		require.Error(t, err)
	})
}

func TestAdvanceDiscoverySequence_NeverMovesBack(t *testing.T) {
	s, db := newTestPostgresStorage(t)
	ctx := t.Context()
	require.NoError(t, s.CreateDiscoveryState(ctx, "agg-1", 10))

	require.NoError(t, advanceDiscoverySequence(ctx, db, "agg-1", 20))
	require.NoError(t, advanceDiscoverySequence(ctx, db, "agg-1", 15))

	seq, err := s.GetDiscoverySequenceNumber(ctx, "agg-1")
	require.NoError(t, err)
	require.Equal(t, 20, seq)

	require.ErrorContains(t, advanceDiscoverySequence(ctx, db, "missing", 1), "discovery record not found")
}

func TestUpdateMessageStatus_TimeoutDoesNotReplaceFinalStatus(t *testing.T) {
	s, db := newTestPostgresStorage(t)
	ctx := t.Context()
	var id protocol.Bytes32
	id[0] = 1
	_, err := db.ExecContext(ctx, `INSERT INTO indexer.messages (message_id, message, status, source_chain_selector, dest_chain_selector, ingestion_timestamp)
		VALUES ($1, '{}', $2, 1, 2, now())`, id.String(), common.MessageProcessing.String())
	require.NoError(t, err)

	status := func() string {
		var st string
		require.NoError(t, db.GetContext(ctx, &st, `SELECT status FROM indexer.messages WHERE message_id = $1`, id.String()))
		return st
	}

	require.NoError(t, s.UpdateMessageStatus(ctx, id, common.MessageSuccessful, ""))
	require.Equal(t, common.MessageSuccessful.String(), status())

	require.NoError(t, s.UpdateMessageStatus(ctx, id, common.MessageTimeout, "late timeout"))
	require.Equal(t, common.MessageSuccessful.String(), status(), "TIMEOUT must not replace SUCCESSFUL")

	require.NoError(t, s.UpdateMessageStatus(ctx, id, common.MessageSuccessful, ""), "a repeated SUCCESSFUL write is not an error")

	var missing protocol.Bytes32
	missing[0] = 2
	require.ErrorContains(t, s.UpdateMessageStatus(ctx, missing, common.MessageSuccessful, ""), "message not found")
}

func TestUpdateMessageStatus_SuccessReplacesTimeout(t *testing.T) {
	s, db := newTestPostgresStorage(t)
	ctx := t.Context()
	var id protocol.Bytes32
	id[0] = 3
	_, err := db.ExecContext(ctx, `INSERT INTO indexer.messages (message_id, message, status, source_chain_selector, dest_chain_selector, ingestion_timestamp)
		VALUES ($1, '{}', $2, 1, 2, now())`, id.String(), common.MessageTimeout.String())
	require.NoError(t, err)

	require.NoError(t, s.UpdateMessageStatus(ctx, id, common.MessageSuccessful, ""))
	var st string
	require.NoError(t, db.GetContext(ctx, &st, `SELECT status FROM indexer.messages WHERE message_id = $1`, id.String()))
	require.Equal(t, common.MessageSuccessful.String(), st)
}
