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

// The lock behavior is tested in common/pgadvisorylock; this checks the indexer key and wiring.
func TestTryAcquireDiscoveryLock(t *testing.T) {
	s, _ := newTestPostgresStorage(t)

	lock, ok, err := s.TryAcquireDiscoveryLock(t.Context(), time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	_, ok, err = s.TryAcquireDiscoveryLock(t.Context(), time.Minute)
	require.NoError(t, err)
	require.False(t, ok)

	lock.Release()
	lock, ok, err = s.TryAcquireDiscoveryLock(t.Context(), time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	lock.Release()
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
