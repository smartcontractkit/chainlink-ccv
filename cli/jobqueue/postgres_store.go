package jobqueue

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"sort"
	"strings"
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
	return s.ListFailedFiltered(ctx, queues, ownerID, nil, limit)
}

// ListFailedFiltered applies exact message IDs before ordering and the per-queue limit.
func (s *PostgresStore) ListFailedFiltered(ctx context.Context, queues []QueueType, ownerID string, messageIDs [][]byte, limit int) ([]ArchivedJob, error) {
	if limit < 0 {
		return nil, fmt.Errorf("limit must be non-negative")
	}
	if len(queues) == 0 {
		queues = []QueueType{QueueTypeTaskVerifier, QueueTypeStorageWriter}
	}

	var results []ArchivedJob

	for _, q := range queues {
		_, archiveTable, err := tableNames(q)
		if err != nil {
			return nil, err
		}

		jobs, err := s.listFailedFromTable(ctx, archiveTable, ownerID, messageIDs, limit, q)
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
	messageIDs [][]byte,
	limit int,
	queue QueueType,
) ([]ArchivedJob, error) {
	query := fmt.Sprintf(`
		SELECT job_id, message_id, owner_id, chain_selector,
		       status, attempt_count, COALESCE(last_error, ''), created_at,
		       completed_at, retry_deadline, failure_category
		FROM %s
		WHERE status = 'failed'
	`, archiveTable)

	args := []any{}

	if ownerID != "" {
		query += fmt.Sprintf(" AND owner_id = $%d", len(args)+1)
		args = append(args, ownerID)
	}

	if len(messageIDs) > 0 {
		placeholders := make([]string, len(messageIDs))
		for i, id := range messageIDs {
			placeholders[i] = fmt.Sprintf("$%d", len(args)+1)
			args = append(args, id)
		}
		query += " AND message_id IN (" + strings.Join(placeholders, ",") + ")"
	}
	query += " ORDER BY created_at DESC, job_id DESC"

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
			failureCategory  string
		)

		if err := rows.Scan(
			&jobID, &messageID, &ownerIDVal, &chainSelectorStr,
			&status, &attemptCount, &lastError, &createdAt,
			&archivedAt, &retryDeadline, &failureCategory,
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
			FailureCategory: failureCategory,
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
	_, err := s.Reschedule(ctx, queue, ownerID, jobID, nil, retryDuration)
	return err
}

func (s *PostgresStore) RescheduleByMessageID(ctx context.Context, queue QueueType, ownerID string, messageID []byte, retryDuration time.Duration) error {
	_, err := s.Reschedule(ctx, queue, ownerID, "", messageID, retryDuration)
	return err
}

// Reschedule locks matching failed rows and restores the selected UUID/owner in one transaction.
// Ambiguity, a missing target or an active-job conflict leave the archive intact.
// A successful result contains the resolved JobID, OwnerID and Queue.
func (s *PostgresStore) Reschedule(ctx context.Context, queue QueueType, ownerID, jobID string, messageID []byte, retryDuration time.Duration) (ArchivedJob, error) {
	var selected ArchivedJob
	active, archive, err := tableNames(queue)
	if err != nil {
		return selected, err
	}
	if (jobID == "") == (len(messageID) == 0) || retryDuration <= 0 {
		return selected, fmt.Errorf("select exactly one job ID or message ID and a positive retry duration")
	}
	column, value := "job_id", any(jobID)
	if jobID == "" {
		column, value = "message_id", messageID
	}
	err = sqlutil.TransactDataSource(ctx, s.ds, nil, func(tx sqlutil.DataSource) error {
		query := fmt.Sprintf("SELECT job_id, owner_id FROM %s WHERE status = 'failed' AND %s = $1", archive, column)
		args := []any{value}
		if ownerID != "" {
			query += " AND owner_id = $2"
			args = append(args, ownerID)
		}
		query += " ORDER BY owner_id, job_id FOR UPDATE"
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		owners := make(map[string]struct{})
		count := 0
		for rows.Next() {
			if err := rows.Scan(&selected.JobID, &selected.OwnerID); err != nil {
				return err
			}
			owners[selected.OwnerID] = struct{}{}
			count++
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("no failed job matches in queue %s for owner %q", queue, ownerID)
		}
		if len(owners) > 1 {
			candidates := make([]string, 0, len(owners))
			for owner := range owners {
				candidates = append(candidates, owner)
			}
			sort.Strings(candidates)
			return fmt.Errorf("multiple owners match: %s; select --verifier-id", strings.Join(candidates, ", "))
		}
		if count > 1 {
			return fmt.Errorf("multiple failed jobs match owner %q; select one with --job-id", selected.OwnerID)
		}
		store := NewPostgresStore(tx)
		affected, err := store.restoreFromArchive(ctx, active, archive, selected.OwnerID, "job_id", selected.JobID, retryDuration)
		if err != nil {
			return fmt.Errorf("restore failed (an active job may already exist): %w", err)
		}
		if affected != 1 {
			return fmt.Errorf("selected archive job changed; nothing restored")
		}
		selected.Queue = queue
		return nil
	})
	return selected, err
}

// restoreFromArchive is the shared CTE that deletes a row from the archive and inserts it into
// the active table with a fresh status, attempt count, and retry deadline.
// idColumn is either "job_id" or "message_id"; idValue is the corresponding filter value.
// A unique-constraint violation on the active table is intentionally surfaced as an error so the
// caller is aware that the job already exists there; silently discarding the INSERT would delete
// the archive record with no backup.
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
	`, archiveTable, idColumn, activeTable)

	result, err := s.ds.ExecContext(ctx, query, idValue, ownerID, newRetryDeadline)
	if err != nil {
		return 0, fmt.Errorf("failed to reschedule job: %w", err)
	}

	return result.RowsAffected()
}
