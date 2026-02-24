package jobqueue

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// PostgresJobQueue implements JobQueue interface using PostgreSQL as the backing store.
// It uses row-level locking with SKIP LOCKED for efficient concurrent processing.
type PostgresJobQueue[T Jobable] struct {
	db          *sql.DB
	config      QueueConfig
	logger      logger.Logger
	tableName   string
	archiveName string
	ownerID     string
}

// NewPostgresJobQueue creates a new PostgreSQL-backed job queue.
// The table must already exist with the appropriate schema.
func NewPostgresJobQueue[T Jobable](
	db *sql.DB,
	config QueueConfig,
	lggr logger.Logger,
) (*PostgresJobQueue[T], error) {
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	return &PostgresJobQueue[T]{
		db:          db,
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

	// Build bulk insert query
	//nolint:gosec // G201: table name is from config, not user input
	query := fmt.Sprintf(`
		INSERT INTO %s (
			job_id, task_data, status, available_at, created_at, attempt_count, retry_deadline,
			chain_selector, message_id, owner_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, q.tableName)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

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

		_, err = stmt.ExecContext(ctx,
			jobID,
			data,
			JobStatusPending,
			availableAt,
			now,
			0, // attempt_count
			now.Add(q.config.RetryDuration),
			chainSelector,
			messageID,
			q.ownerID,
		)
		if err != nil {
			return fmt.Errorf("failed to insert job %s: %w", jobID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
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
func (q *PostgresJobQueue[T]) Consume(ctx context.Context, batchSize int) ([]Job[T], error) {
	now := time.Now()
	staleBefore := now.Add(-q.config.LockDuration)

	// Select jobs that are:
	// 1. pending/failed and past their available_at, OR
	// 2. processing but started_at is older than lockDuration (stale lock from crashed worker)
	//nolint:gosec // G201: table name is from config, not user input
	query := fmt.Sprintf(`
		UPDATE %s
		SET status = $1,
			started_at = $2,
			attempt_count = attempt_count + 1
		WHERE id IN (
			SELECT id FROM %s
			WHERE owner_id = $3
			  AND (
			    (status IN ($4, $5) AND available_at <= $6)
			    OR
			    (status = $7 AND started_at IS NOT NULL AND started_at <= $8)
			  )
			ORDER BY available_at ASC, id ASC
			LIMIT $9
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, job_id, task_data, attempt_count, retry_deadline, created_at, started_at, chain_selector, message_id
	`, q.tableName, q.tableName)

	rows, err := q.db.QueryContext(ctx, query,
		JobStatusProcessing, // $1
		now,                 // $2 started_at
		q.ownerID,           // $3
		JobStatusPending,    // $4
		JobStatusFailed,     // $5
		now,                 // $6 available_at <=
		JobStatusProcessing, // $7 stale processing
		staleBefore,         // $8 started_at <=
		batchSize,           // $9
	)
	if err != nil {
		return nil, fmt.Errorf("failed to consume jobs: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var jobs []Job[T]
	for rows.Next() {
		var (
			id            int64
			jobID         string
			dataJSON      []byte
			attemptCount  int
			retryDeadline time.Time
			createdAt     time.Time
			startedAt     sql.NullTime
			chainSelector sql.NullString
			messageID     sql.NullString
		)

		err := rows.Scan(&id, &jobID, &dataJSON, &attemptCount, &retryDeadline, &createdAt, &startedAt, &chainSelector, &messageID)
		if err != nil {
			q.logger.Errorw("Failed to scan job row", "error", err)
			continue
		}

		var payload T
		if err := json.Unmarshal(dataJSON, &payload); err != nil {
			q.logger.Errorw("Failed to unmarshal job payload",
				"jobID", jobID,
				"error", err,
			)
			continue
		}

		job := Job[T]{
			ID:            jobID,
			Payload:       payload,
			AttemptCount:  attemptCount,
			RetryDeadline: retryDeadline,
			CreatedAt:     createdAt,
			ChainSelector: chainSelector.String,
			MessageID:     messageID.String,
		}

		if startedAt.Valid {
			job.StartedAt = &startedAt.Time
		}

		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job rows: %w", err)
	}

	q.logger.Debugw("Consumed jobs from queue",
		"queue", q.config.Name,
		"count", len(jobs),
		"requested", batchSize,
	)

	return jobs, nil
}

// Complete marks jobs as successfully processed.
func (q *PostgresJobQueue[T]) Complete(ctx context.Context, jobIDs ...string) error {
	if len(jobIDs) == 0 {
		return nil
	}

	// Move to archive table for audit trail
	// Note: This query works for both verification_tasks (without task_job_id)
	// and verification_results (with task_job_id) by selecting all columns
	//nolint:gosec // G201: table names are from config, not user input
	query := fmt.Sprintf(`
		WITH completed AS (
			DELETE FROM %s
			WHERE job_id = ANY($1)
			  AND owner_id = $2
			RETURNING *
		)
		INSERT INTO %s
		SELECT *, NOW() as completed_at
		FROM completed
	`, q.tableName, q.archiveName)

	result, err := q.db.ExecContext(ctx, query, pq.Array(jobIDs), q.ownerID)
	if err != nil {
		return fmt.Errorf("failed to complete jobs: %w", err)
	}

	affected, _ := result.RowsAffected()
	q.logger.Debugw("Completed jobs",
		"queue", q.config.Name,
		"count", affected,
	)

	return nil
}

// Retry schedules jobs for retry after delay.
func (q *PostgresJobQueue[T]) Retry(ctx context.Context, delay time.Duration, errors map[string]error, jobIDs ...string) error {
	if len(jobIDs) == 0 {
		return nil
	}

	availableAt := time.Now().Add(delay)

	// Check if retry deadline has passed
	//nolint:gosec // G201: table name is from config, not user input
	query := fmt.Sprintf(`
		UPDATE %s
		SET status = CASE
				WHEN NOW() >= retry_deadline THEN $1
				ELSE $2
			END,
			available_at = $3,
			last_error = $4
		WHERE job_id = $5
		  AND owner_id = $6
		RETURNING job_id, status
	`, q.tableName)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare retry statement: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	var failed []string
	var retried []string

	for _, jobID := range jobIDs {
		errMsg := ""
		if err, ok := errors[jobID]; ok && err != nil {
			errMsg = err.Error()
		}

		var resultJobID string
		var resultStatus string

		err := stmt.QueryRowContext(ctx,
			JobStatusFailed,
			JobStatusPending,
			availableAt,
			errMsg,
			jobID,
			q.ownerID,
		).Scan(&resultJobID, &resultStatus)
		if err != nil {
			q.logger.Errorw("Failed to retry job",
				"jobID", jobID,
				"error", err,
			)
			continue
		}

		// Use the status decided by the database to avoid race condition
		// between SQL NOW() and Go time.Now()
		if resultStatus == string(JobStatusFailed) {
			failed = append(failed, resultJobID)
		} else {
			retried = append(retried, resultJobID)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit retry transaction: %w", err)
	}

	q.logger.Infow("Retried jobs",
		"queue", q.config.Name,
		"retried", len(retried),
		"failed", len(failed),
		"delay", delay,
	)

	return nil
}

// Fail marks jobs as permanently failed.
func (q *PostgresJobQueue[T]) Fail(ctx context.Context, errors map[string]error, jobIDs ...string) error {
	if len(jobIDs) == 0 {
		return nil
	}

	//nolint:gosec // G201: table name is from config, not user input
	query := fmt.Sprintf(`
		UPDATE %s
		SET status = $1,
			last_error = $2
		WHERE job_id = $3
		  AND owner_id = $4
	`, q.tableName)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare fail statement: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	for _, jobID := range jobIDs {
		errMsg := ""
		if err, ok := errors[jobID]; ok && err != nil {
			errMsg = err.Error()
		}

		_, err := stmt.ExecContext(ctx, JobStatusFailed, errMsg, jobID, q.ownerID)
		if err != nil {
			q.logger.Errorw("Failed to mark job as failed",
				"jobID", jobID,
				"error", err,
			)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit fail transaction: %w", err)
	}

	q.logger.Infow("Failed jobs",
		"queue", q.config.Name,
		"count", len(jobIDs),
	)

	return nil
}

// Cleanup archives or deletes old jobs.
func (q *PostgresJobQueue[T]) Cleanup(ctx context.Context, retentionPeriod time.Duration) (int, error) {
	cutoff := time.Now().Add(-retentionPeriod)

	//nolint:gosec // G201: table name is from config, not user input
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE completed_at < $1
		  AND owner_id = $2
	`, q.archiveName)

	result, err := q.db.ExecContext(ctx, query, cutoff, q.ownerID)
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

// Name returns the queue name.
func (q *PostgresJobQueue[T]) Name() string {
	return q.config.Name
}
