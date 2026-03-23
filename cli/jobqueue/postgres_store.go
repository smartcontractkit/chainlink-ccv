package jobqueue

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// PostgresStore implements Store using a PostgreSQL database.
type PostgresStore struct {
	ds sqlutil.DataSource
}

// NewPostgresStore returns a new PostgresStore.
func NewPostgresStore(ds sqlutil.DataSource) *PostgresStore {
	return &PostgresStore{ds: ds}
}

// tableNames returns the active and archive table names for the given queue type.
func tableNames(q QueueType) (active, archive string, err error) {
	switch q {
	case QueueTypeTaskVerifier:
		return vtypes.TaskVerifierJobsTableName, vtypes.TaskVerifierJobsTableName + "_archive", nil
	case QueueTypeStorageWriter:
		return vtypes.StorageWriterJobsTableName, vtypes.StorageWriterJobsTableName + "_archive", nil
	default:
		return "", "", fmt.Errorf("unknown queue type %q: must be %q or %q",
			q, QueueTypeTaskVerifier, QueueTypeStorageWriter)
	}
}

// ListFailed returns failed jobs from the archive table(s).
// An empty queues slice queries both queues.
// An empty ownerID queries all verifier IDs.
func (s *PostgresStore) ListFailed(ctx context.Context, queues []QueueType, ownerID string, limit int) ([]ArchivedJob, error) {
	if len(queues) == 0 {
		queues = []QueueType{QueueTypeTaskVerifier, QueueTypeStorageWriter}
	}

	var results []ArchivedJob

	for _, q := range queues {
		_, archiveTable, err := tableNames(q)
		if err != nil {
			return nil, err
		}

		jobs, err := s.listFailedFromTable(ctx, archiveTable, ownerID, limit, q)
		if err != nil {
			return nil, fmt.Errorf("failed to list failed jobs from %s: %w", archiveTable, err)
		}
		results = append(results, jobs...)
	}

	return results, nil
}

func (s *PostgresStore) listFailedFromTable(
	ctx context.Context,
	archiveTable string,
	ownerID string,
	limit int,
	queue QueueType,
) ([]ArchivedJob, error) {
	query := fmt.Sprintf(`
		SELECT job_id, message_id, owner_id, chain_selector,
		       status, attempt_count, COALESCE(last_error, ''), created_at,
		       completed_at, retry_deadline
		FROM %s
		WHERE status = 'failed'
	`, archiveTable)

	args := []any{}

	if ownerID != "" {
		query += fmt.Sprintf(" AND owner_id = $%d", len(args)+1)
		args = append(args, ownerID)
	}

	query += " ORDER BY created_at DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", len(args)+1)
		args = append(args, limit)
	}

	rows, err := s.ds.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var jobs []ArchivedJob
	for rows.Next() {
		var (
			jobID            string
			messageID        []byte
			ownerIDVal       string
			chainSelectorStr string
			status           string
			attemptCount     int
			lastError        string
			createdAt        time.Time
			archivedAt       sql.NullTime
			retryDeadline    time.Time
		)

		if err := rows.Scan(
			&jobID, &messageID, &ownerIDVal, &chainSelectorStr,
			&status, &attemptCount, &lastError, &createdAt,
			&archivedAt, &retryDeadline,
		); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		chainSelectorBig := new(big.Int)
		if _, ok := chainSelectorBig.SetString(chainSelectorStr, 10); !ok {
			return nil, fmt.Errorf("failed to parse chain_selector %q", chainSelectorStr)
		}

		job := ArchivedJob{
			JobID:         jobID,
			MessageID:     messageID,
			OwnerID:       ownerIDVal,
			ChainSelector: chainSelectorBig.Uint64(),
			Status:        status,
			AttemptCount:  attemptCount,
			LastError:     lastError,
			CreatedAt:     createdAt,
			RetryDeadline: retryDeadline,
			Queue:         queue,
		}
		if archivedAt.Valid {
			t := archivedAt.Time
			job.ArchivedAt = &t
		}

		jobs = append(jobs, job)
	}

	return jobs, rows.Err()
}

// RescheduleByJobID moves a failed job from the archive back to the active table.
func (s *PostgresStore) RescheduleByJobID(
	ctx context.Context,
	queue QueueType,
	ownerID string,
	jobID string,
	retryDuration time.Duration,
) error {
	activeTable, archiveTable, err := tableNames(queue)
	if err != nil {
		return err
	}

	affected, err := s.restoreFromArchive(ctx, activeTable, archiveTable, ownerID, "job_id", jobID, retryDuration)
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("no failed job with job_id=%q found in %s for owner_id=%q", jobID, archiveTable, ownerID)
	}
	return nil
}

// RescheduleByMessageID moves a failed job from the archive back to the active table.
func (s *PostgresStore) RescheduleByMessageID(
	ctx context.Context,
	queue QueueType,
	ownerID string,
	messageID []byte,
	retryDuration time.Duration,
) error {
	activeTable, archiveTable, err := tableNames(queue)
	if err != nil {
		return err
	}

	affected, err := s.restoreFromArchive(ctx, activeTable, archiveTable, ownerID, "message_id", messageID, retryDuration)
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("no failed job with the given message_id found in %s for owner_id=%q", archiveTable, ownerID)
	}
	return nil
}

// restoreFromArchive is the shared CTE that deletes a row from the archive and inserts it into
// the active table with a fresh status, attempt count, and retry deadline.
// idColumn is either "job_id" or "message_id"; idValue is the corresponding filter value.
func (s *PostgresStore) restoreFromArchive(
	ctx context.Context,
	activeTable, archiveTable string,
	ownerID string,
	idColumn string,
	idValue any,
	retryDuration time.Duration,
) (int64, error) {
	newRetryDeadline := time.Now().Add(retryDuration)

	query := fmt.Sprintf(`
		WITH archived AS (
			DELETE FROM %s
			WHERE %s = $1
			  AND owner_id = $2
			  AND status = 'failed'
			RETURNING id, job_id, owner_id, chain_selector, message_id, task_data, created_at
		)
		INSERT INTO %s (
			id, job_id, owner_id, chain_selector, message_id, task_data,
			status, created_at, available_at, attempt_count, retry_deadline
		)
		SELECT id, job_id, owner_id, chain_selector, message_id, task_data,
		       'pending', created_at, NOW(), 0, $3
		FROM archived
		ON CONFLICT (owner_id, chain_selector, message_id) DO NOTHING
	`, archiveTable, idColumn, activeTable)

	result, err := s.ds.ExecContext(ctx, query, idValue, ownerID, newRetryDeadline)
	if err != nil {
		return 0, fmt.Errorf("failed to reschedule job: %w", err)
	}

	return result.RowsAffected()
}
