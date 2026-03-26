package jobqueue

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// PostgresJobQueue implements JobQueue interface using PostgreSQL as the backing store.
// It uses row-level locking with SKIP LOCKED for efficient concurrent processing.
type PostgresJobQueue[T Jobable] struct {
	ds          sqlutil.DataSource
	config      QueueConfig
	logger      logger.Logger
	tableName   string
	archiveName string
	ownerID     string
}

// NewPostgresJobQueue creates a new PostgreSQL-backed job queue.
// The table must already exist with the appropriate schema.
func NewPostgresJobQueue[T Jobable](
	ds sqlutil.DataSource,
	config QueueConfig,
	lggr logger.Logger,
) (*PostgresJobQueue[T], error) {
	if ds == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	return &PostgresJobQueue[T]{
		ds:          ds,
		config:      config,
		logger:      lggr,
		tableName:   config.Name,
		archiveName: config.Name + "_archive",
		ownerID:     config.OwnerID,
	}, nil
}

// Publish adds jobs to the queue.
func (q *PostgresJobQueue[T]) Publish(ctx context.Context, jobs ...T) error {
	return q.PublishWithDelay(ctx, 0, jobs...)
}

// PublishWithDelay adds jobs with a delay before they become available.
func (q *PostgresJobQueue[T]) PublishWithDelay(ctx context.Context, delay time.Duration, jobs ...T) error {
	if len(jobs) == 0 {
		return nil
	}

	availableAt := time.Now().Add(delay)

	// Build bulk insert query with ON CONFLICT DO NOTHING to avoid duplicates
	// when the verifier is restarted
	query := fmt.Sprintf(`
		INSERT INTO %s (
			job_id, task_data, status, available_at, created_at, attempt_count, retry_deadline,
			chain_selector, message_id, owner_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (owner_id, chain_selector, message_id) DO NOTHING
	`, q.tableName)

	err := sqlutil.TransactDataSource(ctx, q.ds, nil, func(tx sqlutil.DataSource) error {
		stmt, err := tx.PrepareContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to prepare statement: %w", err)
		}
		defer func() {
			_ = stmt.Close()
		}()

		for _, job := range jobs {
			jobID := uuid.New().String()

			// Serialize payload to JSON
			data, err := json.Marshal(job)
			if err != nil {
				return fmt.Errorf("failed to marshal job payload: %w", err)
			}

			// Extract chain selector and message ID from the job
			chainSelector, messageID := job.JobKey()

			now := time.Now()

			// Convert uint64 to string for postgres numeric(20,0) - avoids int64 overflow
			chainSelectorStr := new(big.Int).SetUint64(chainSelector).String()

			_, err = stmt.ExecContext(ctx,
				jobID,
				data,
				JobStatusPending,
				availableAt,
				now,
				0, // attempt_count
				now.Add(q.config.RetryDuration),
				chainSelectorStr,
				messageID,
				q.ownerID,
			)
			if err != nil {
				return fmt.Errorf("failed to insert job %s: %w", jobID, err)
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	q.logger.Debugw("Published jobs to queue",
		"queue", q.config.Name,
		"count", len(jobs),
		"delay", delay,
	)

	return nil
}

// Consume retrieves and locks jobs for processing.
// Jobs stuck in 'processing' longer than the configured LockDuration are automatically reclaimed.
//
// Two separate queries replace the former single OR query. Combining both predicates
// (pending + stale-processing) in one OR forced a full Seq Scan + external-merge disk sort
// on every poll because the planner could not use either partial index. Each query below
// targets its own dedicated partial index and allows Postgres to stream rows in index order
// with FOR UPDATE SKIP LOCKED — O(batchSize) instead of O(table size).
//
// Stale reclamation always runs first with the full batchSize limit. The pending limit is
// then computed in memory as batchSize - len(staleJobs), so pending always fills a full
// batch when there are no stale jobs, and stale jobs can never be starved by pending backlog.
func (q *PostgresJobQueue[T]) Consume(ctx context.Context, batchSize int) ([]Job[T], error) {
	now := time.Now()
	staleBefore := now.Add(-q.config.LockDuration)

	// Phase 1: reclaim stale processing jobs (crashed-worker recovery) — always runs first.
	// Running stale before pending lets us compute the exact remaining capacity for pending
	// in memory, so pending always fills up to batchSize when there are no stale jobs.
	// Uses idx_stale (owner_id, started_at, id) WHERE status='processing' AND started_at IS NOT NULL.
	staleQuery := fmt.Sprintf(`
		UPDATE %[1]s
		SET status = $1,
		    started_at = $2,
		    attempt_count = attempt_count + 1
		WHERE id IN (
		    SELECT id FROM %[1]s
		    WHERE owner_id = $3
		      AND status = $4
		      AND started_at IS NOT NULL
		      AND started_at <= $5
		    ORDER BY started_at ASC, id ASC
		    LIMIT $6
		    FOR UPDATE SKIP LOCKED
		)
		RETURNING id, job_id, task_data, attempt_count, retry_deadline, created_at, started_at, chain_selector, message_id
	`, q.tableName)

	jobs, failedToDeserialize, err := q.runConsumeQuery(ctx, staleQuery,
		JobStatusProcessing, // $1
		now,                 // $2 started_at
		q.ownerID,           // $3
		JobStatusProcessing, // $4
		staleBefore,         // $5 started_at <=
		batchSize,           // $6
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reclaim stale jobs: %w", err)
	}

	// Phase 2: pending jobs — always fills remaining capacity up to batchSize.
	// pendingLimit is computed in memory from the stale result: when stale returns nothing,
	// pending gets the full batchSize; when stale is at quota, pending gets batchSize - staleQuota.
	// Uses idx_consume (owner_id, available_at, id) WHERE status='pending'.
	pendingLimit := batchSize - len(jobs)
	pendingQuery := fmt.Sprintf(`
		UPDATE %[1]s
		SET status = $1,
		    started_at = $2,
		    attempt_count = attempt_count + 1
		WHERE id IN (
		    SELECT id FROM %[1]s
		    WHERE owner_id = $3
		      AND status = $4
		      AND available_at <= $5
		    ORDER BY available_at ASC, id ASC
		    LIMIT $6
		    FOR UPDATE SKIP LOCKED
		)
		RETURNING id, job_id, task_data, attempt_count, retry_deadline, created_at, started_at, chain_selector, message_id
	`, q.tableName)

	pendingJobs, pendingFailures, err := q.runConsumeQuery(ctx, pendingQuery,
		JobStatusProcessing, // $1
		now,                 // $2 started_at
		q.ownerID,           // $3
		JobStatusPending,    // $4
		now,                 // $5 available_at <=
		pendingLimit,        // $6
	)
	if err != nil {
		return nil, fmt.Errorf("failed to consume pending jobs: %w", err)
	}
	jobs = append(jobs, pendingJobs...)
	maps.Copy(failedToDeserialize, pendingFailures)

	// Mark jobs that failed to deserialize as permanently failed
	// to prevent them from being stuck in 'processing' state forever.
	if len(failedToDeserialize) > 0 {
		failedJobIDs := make([]string, 0, len(failedToDeserialize))
		for jobID := range failedToDeserialize {
			failedJobIDs = append(failedJobIDs, jobID)
		}

		q.logger.Errorw("Jobs failed to deserialize, marking as failed",
			"count", len(failedJobIDs),
			"queue", q.config.Name,
		)

		if err := q.Fail(ctx, failedToDeserialize, failedJobIDs...); err != nil {
			q.logger.Errorw("Failed to mark deserialization-failed jobs as failed",
				"error", err,
				"count", len(failedJobIDs),
			)
		}
	}

	q.logger.Debugw("Consumed jobs from queue",
		"queue", q.config.Name,
		"count", len(jobs),
		"requested", batchSize,
	)

	return jobs, nil
}

// runConsumeQuery executes a consume UPDATE query and scans the RETURNING rows into
// Job[T] values. Jobs that fail to deserialize are returned in a separate map so the
// caller can immediately archive them as permanently failed.
func (q *PostgresJobQueue[T]) runConsumeQuery(ctx context.Context, query string, args ...any) ([]Job[T], map[string]error, error) {
	rows, err := q.ds.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute consume query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []Job[T]
	failedToDeserialize := make(map[string]error)

	for rows.Next() {
		var (
			id               int64
			jobID            string
			dataJSON         []byte
			attemptCount     int
			retryDeadline    time.Time
			createdAt        time.Time
			startedAt        sql.NullTime
			chainSelectorStr string
			messageID        []byte
		)

		err := rows.Scan(&id, &jobID, &dataJSON, &attemptCount, &retryDeadline, &createdAt, &startedAt, &chainSelectorStr, &messageID)
		if err != nil {
			q.logger.Errorw("Failed to scan job row", "error", err)
			// We can't get jobID if scan failed, so we can't mark it as failed.
			// This should be extremely rare (database corruption).
			continue
		}

		chainSelectorBig := new(big.Int)
		if _, ok := chainSelectorBig.SetString(chainSelectorStr, 10); !ok {
			scanErr := fmt.Errorf("failed to parse chain selector: %s", chainSelectorStr)
			q.logger.Errorw("Failed to parse chain selector",
				"jobID", jobID,
				"chainSelector", chainSelectorStr,
			)
			failedToDeserialize[jobID] = scanErr
			continue
		}
		chainSelector := chainSelectorBig.Uint64()

		var payload T
		if err := json.Unmarshal(dataJSON, &payload); err != nil {
			q.logger.Errorw("Failed to unmarshal job payload",
				"jobID", jobID,
				"error", err,
			)
			failedToDeserialize[jobID] = fmt.Errorf("failed to unmarshal payload: %w", err)
			continue
		}

		job := Job[T]{
			ID:            jobID,
			Payload:       payload,
			AttemptCount:  attemptCount,
			RetryDeadline: retryDeadline,
			CreatedAt:     createdAt,
			ChainSelector: chainSelector,
			MessageID:     messageID,
		}
		if startedAt.Valid {
			job.StartedAt = &startedAt.Time
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating job rows: %w", err)
	}

	return jobs, failedToDeserialize, nil
}

// Complete marks jobs as successfully processed and moves them to the archive.
func (q *PostgresJobQueue[T]) Complete(ctx context.Context, jobIDs ...string) error {
	if len(jobIDs) == 0 {
		return nil
	}

	// Single atomic operation: delete from the active table and insert into the archive
	// with status overridden to 'completed'. All job queue tables share the same schema
	// so we can enumerate columns explicitly.
	query := fmt.Sprintf(`
		WITH completed AS (
			DELETE FROM %s
			WHERE job_id = ANY($1)
			  AND owner_id = $2
			RETURNING id, job_id, owner_id, chain_selector, message_id, task_data,
			          created_at, available_at, started_at, attempt_count, retry_deadline, last_error
		)
		INSERT INTO %s (
			id, job_id, owner_id, chain_selector, message_id, task_data,
			status, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
			completed_at
		)
		SELECT id, job_id, owner_id, chain_selector, message_id, task_data,
		       $3, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
		       NOW()
		FROM completed
	`, q.tableName, q.archiveName)

	result, err := q.ds.ExecContext(ctx, query, pq.Array(jobIDs), q.ownerID, JobStatusCompleted)
	if err != nil {
		return fmt.Errorf("failed to complete and archive jobs: %w", err)
	}

	affected, _ := result.RowsAffected()
	q.logger.Debugw("Completed jobs",
		"queue", q.config.Name,
		"count", affected,
	)

	return nil
}

// Retry schedules jobs for retry after delay.
// If the retry deadline has been exceeded, jobs are marked as failed and archived.
func (q *PostgresJobQueue[T]) Retry(ctx context.Context, delay time.Duration, errors map[string]error, jobIDs ...string) error {
	if len(jobIDs) == 0 {
		return nil
	}

	availableAt := time.Now().Add(delay)

	// Build parallel arrays for the UNNEST bulk update.
	// All jobs share the same availableAt; only the error message differs per job.
	errMsgsArr := make([]string, len(jobIDs))
	for i, id := range jobIDs {
		if e, ok := errors[id]; ok && e != nil {
			errMsgsArr[i] = e.Error()
		}
	}

	var failed []string
	var retried []string

	err := sqlutil.TransactDataSource(ctx, q.ds, nil, func(tx sqlutil.DataSource) error {
		// Single bulk UPDATE replaces the former N-round-trip per-job loop.
		// UNNEST produces one row per job with its error message; the CASE expression
		// lets the database authoritatively decide whether the retry deadline has been exceeded.
		query := fmt.Sprintf(`
			UPDATE %s AS t
			SET status = CASE
			        WHEN NOW() >= t.retry_deadline THEN $1
			        ELSE $2
			    END,
			    available_at = $3,
			    last_error = v.error_msg
			FROM UNNEST($4::text[], $5::text[]) AS v(job_id, error_msg)
			WHERE t.job_id = v.job_id::uuid
			  AND t.owner_id = $6
			RETURNING t.job_id, t.status
		`, q.tableName)

		rows, err := tx.QueryContext(ctx, query,
			JobStatusFailed,      // $1
			JobStatusPending,     // $2
			availableAt,          // $3
			pq.Array(jobIDs),     // $4
			pq.Array(errMsgsArr), // $5
			q.ownerID,            // $6
		)
		if err != nil {
			return fmt.Errorf("failed to bulk-update jobs for retry: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var resultJobID, resultStatus string
			if err := rows.Scan(&resultJobID, &resultStatus); err != nil {
				q.logger.Errorw("Failed to scan retry result row", "error", err)
				continue
			}
			// Use the status decided by the database to avoid a race condition
			// between SQL NOW() and Go time.Now().
			if resultStatus == string(JobStatusFailed) {
				failed = append(failed, resultJobID)
			} else {
				retried = append(retried, resultJobID)
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("error iterating retry result rows: %w", err)
		}

		// Archive jobs that exceeded the retry deadline within the same transaction.
		// Uses explicit column names (not SELECT *) so the query is robust to future
		// schema changes on the active table.
		if len(failed) > 0 {
			archiveQuery := fmt.Sprintf(`
				WITH failed AS (
					DELETE FROM %s
					WHERE job_id = ANY($1)
					  AND owner_id = $2
					  AND status = $3
					RETURNING id, job_id, owner_id, chain_selector, message_id, task_data,
					          status, created_at, available_at, started_at, attempt_count, retry_deadline, last_error
				)
				INSERT INTO %s (
					id, job_id, owner_id, chain_selector, message_id, task_data,
					status, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
					completed_at
				)
				SELECT id, job_id, owner_id, chain_selector, message_id, task_data,
				       status, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
				       NOW()
				FROM failed
			`, q.tableName, q.archiveName)

			result, err := tx.ExecContext(ctx, archiveQuery, pq.Array(failed), q.ownerID, JobStatusFailed)
			if err != nil {
				return fmt.Errorf("failed to archive jobs that exceeded retry deadline: %w", err)
			}

			affected, _ := result.RowsAffected()
			q.logger.Infow("Archived jobs that exceeded retry deadline",
				"queue", q.config.Name,
				"count", affected)
		}

		return nil
	})
	if err != nil {
		return err
	}

	q.logger.Infow("Retried jobs",
		"queue", q.config.Name,
		"retried", len(retried),
		"failed", len(failed),
		"delay", delay,
	)

	return nil
}

// Fail marks jobs as permanently failed and moves them to the archive.
// This ensures failed jobs don't remain in the active queue indefinitely.
//
// A single bulk CTE replaces the former N-round-trip per-job loop. UNNEST supplies
// per-job error messages and the DELETE+INSERT within the CTE is inherently atomic,
// mirroring how Complete() handles bulk archival.
func (q *PostgresJobQueue[T]) Fail(ctx context.Context, errors map[string]error, jobIDs ...string) error {
	if len(jobIDs) == 0 {
		return nil
	}

	// Build parallel arrays for the UNNEST input so each job carries its own error message.
	errMsgsArr := make([]string, len(jobIDs))
	for i, id := range jobIDs {
		if e, ok := errors[id]; ok && e != nil {
			errMsgsArr[i] = e.Error()
		}
	}

	// Single bulk CTE: UNNEST the job IDs and error messages, delete from the active
	// table, then join back to attach per-job error messages on insert into the archive.
	// Explicit column names (not SELECT *) keep the query correct if columns are added.
	query := fmt.Sprintf(`
		WITH jobs_input AS (
		    SELECT v.job_id::uuid AS job_id, v.error_msg
		    FROM UNNEST($1::text[], $2::text[]) AS v(job_id, error_msg)
		),
		to_fail AS (
		    DELETE FROM %s t
		    WHERE t.job_id IN (SELECT job_id FROM jobs_input)
		      AND t.owner_id = $3
		    RETURNING t.id, t.job_id, t.owner_id, t.chain_selector, t.message_id, t.task_data,
		              t.created_at, t.available_at, t.started_at, t.attempt_count, t.retry_deadline
		)
		INSERT INTO %s (
		    id, job_id, owner_id, chain_selector, message_id, task_data,
		    status, created_at, available_at, started_at, attempt_count, retry_deadline,
		    last_error, completed_at
		)
		SELECT f.id, f.job_id, f.owner_id, f.chain_selector, f.message_id, f.task_data,
		       $4, f.created_at, f.available_at, f.started_at, f.attempt_count, f.retry_deadline,
		       i.error_msg, NOW()
		FROM to_fail f
		JOIN jobs_input i ON f.job_id = i.job_id
	`, q.tableName, q.archiveName)

	result, err := q.ds.ExecContext(ctx, query,
		pq.Array(jobIDs),     // $1
		pq.Array(errMsgsArr), // $2
		q.ownerID,            // $3
		JobStatusFailed,      // $4
	)
	if err != nil {
		return fmt.Errorf("failed to fail and archive jobs: %w", err)
	}

	affected, _ := result.RowsAffected()
	q.logger.Infow("Failed and archived jobs",
		"queue", q.config.Name,
		"count", affected,
	)

	return nil
}

// Cleanup archives or deletes old jobs.
func (q *PostgresJobQueue[T]) Cleanup(ctx context.Context, retentionPeriod time.Duration) (int, error) {
	cutoff := time.Now().Add(-retentionPeriod)

	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE completed_at < $1
		  AND owner_id = $2
	`, q.archiveName)

	result, err := q.ds.ExecContext(ctx, query, cutoff, q.ownerID)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup archive: %w", err)
	}

	affected, _ := result.RowsAffected()
	q.logger.Infow("Cleaned up archive",
		"queue", q.config.Name,
		"deleted", affected,
		"retention", retentionPeriod,
	)

	return int(affected), nil
}

// Size returns the count of jobs that are pending or processing.
// Failed jobs and archived jobs are excluded from the count.
func (q *PostgresJobQueue[T]) Size(ctx context.Context) (int, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM %s
		WHERE owner_id = $1
		  AND status IN ($2, $3)
	`, q.tableName)

	var count int
	err := q.ds.QueryRowxContext(ctx, query, q.ownerID, JobStatusPending, JobStatusProcessing).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get queue size: %w", err)
	}

	return count, nil
}

// Name returns the queue name.
func (q *PostgresJobQueue[T]) Name() string {
	return q.config.Name
}
