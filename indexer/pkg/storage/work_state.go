package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// The work state queries are constants so that the EXPLAIN test runs the same SQL.
const (
	claimWorkSQL = `
		UPDATE indexer.messages m
		SET attempt_count = m.attempt_count + 1,
		    next_attempt_at = NOW() + make_interval(secs => $2)
		WHERE m.message_id IN (
			SELECT message_id FROM indexer.messages
			WHERE status = $1
			  AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
			  AND COALESCE(retry_deadline, (ingestion_timestamp AT TIME ZONE 'UTC') + make_interval(secs => $3)) > NOW()
			ORDER BY next_attempt_at ASC NULLS FIRST
			LIMIT $4
			FOR UPDATE SKIP LOCKED)
		RETURNING m.message_id, m.attempt_count, COALESCE(m.trace_parent, '')`
	settleFinalSQL = `
			UPDATE indexer.messages SET status = $1, lastErr = $2, next_attempt_at = NULL
			WHERE message_id = $3 AND status = $4 AND attempt_count = $5
			RETURNING status`
	settleRetrySQL = `
			UPDATE indexer.messages
			SET status = CASE WHEN NOW() + make_interval(secs => $1) >= COALESCE(retry_deadline, (ingestion_timestamp AT TIME ZONE 'UTC') + make_interval(secs => $2)) THEN $3 ELSE status END,
			    lastErr = $4,
			    next_attempt_at = NOW() + make_interval(secs => $1)
			WHERE message_id = $5 AND status = $6 AND attempt_count = $7
			RETURNING status`
	expireWorkSQL = `
		UPDATE indexer.messages SET status = $1, lastErr = $2, next_attempt_at = NULL
		WHERE message_id = ANY(ARRAY(
			SELECT message_id FROM indexer.messages
			WHERE status = $3
			  AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
			  AND COALESCE(retry_deadline, (ingestion_timestamp AT TIME ZONE 'UTC') + make_interval(secs => $4)) <= NOW()
			LIMIT $5
			FOR UPDATE SKIP LOCKED))`
	countProcessingSQL = `SELECT COUNT(*) FROM indexer.messages WHERE status = $1`
)

// ClaimWork implements common.IndexerStorage.
// It claims due PROCESSING messages inside their deadline and leases them until NOW() + lease.
func (d *PostgresStorage) ClaimWork(ctx context.Context, limit int, lease, window time.Duration) ([]common.WorkClaim, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := d.ds.QueryContext(ctx, claimWorkSQL,
		common.MessageProcessingString, lease.Seconds(), window.Seconds(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to claim messages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var claims []common.WorkClaim
	for rows.Next() {
		var id string
		var c common.WorkClaim
		if err := rows.Scan(&id, &c.Attempt, &c.TraceParent); err != nil {
			return nil, err
		}
		if c.MessageID, err = protocol.NewBytes32FromString(id); err != nil {
			return nil, err
		}
		claims = append(claims, c)
	}
	return claims, rows.Err()
}

// SettleWork implements common.IndexerStorage. It updates the message only while the claim is still held.
// A retry whose next attempt starts at or after the deadline becomes TIMEOUT; Postgres decides this.
func (d *PostgresStorage) SettleWork(ctx context.Context, s common.WorkSettlement) (common.MessageStatus, error) {
	var status string
	var err error
	switch s.Status {
	case common.MessageSuccessful, common.MessageTimeout:
		err = d.ds.GetContext(ctx, &status, settleFinalSQL,
			s.Status.String(), s.LastErr, s.MessageID.String(), common.MessageProcessingString, s.Attempt)
	case common.MessageProcessing:
		err = d.ds.GetContext(ctx, &status, settleRetrySQL,
			s.RetryDelay.Seconds(), s.Window.Seconds(), common.MessageTimeout.String(), s.LastErr,
			s.MessageID.String(), common.MessageProcessingString, s.Attempt)
	default:
		return common.MessageProcessing, fmt.Errorf("cannot settle with status %s", s.Status)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return common.MessageProcessing, common.ErrClaimLost
	}
	if err != nil {
		return common.MessageProcessing, fmt.Errorf("failed to settle message: %w", err)
	}
	return common.NewMessageStatusFromString(status)
}

// ExpireWork implements common.IndexerStorage. It times out PROCESSING messages that are not leased and are past their deadline.
func (d *PostgresStorage) ExpireWork(ctx context.Context, window time.Duration, limit int) (int64, error) {
	res, err := d.ds.ExecContext(ctx, expireWorkSQL,
		common.MessageTimeout.String(), "retry deadline passed", common.MessageProcessingString, window.Seconds(), limit)
	if err != nil {
		return 0, fmt.Errorf("failed to expire messages: %w", err)
	}
	return res.RowsAffected()
}

// CountProcessingMessages implements common.IndexerStorage.
func (d *PostgresStorage) CountProcessingMessages(ctx context.Context) (int64, error) {
	var n int64
	err := d.ds.GetContext(ctx, &n, countProcessingSQL, common.MessageProcessingString)
	return n, err
}
