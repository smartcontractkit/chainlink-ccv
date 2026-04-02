package replay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

var (
	ErrJobNotFound  = errors.New("replay job not found")
	ErrJobLocked    = errors.New("replay job is locked by another process")
	ErrNoResumable  = errors.New("no resumable replay job found")
	StaleJobTimeout = 5 * time.Minute
)

// Store provides CRUD operations for the replay_jobs table.
type Store struct {
	ds   sqlutil.DataSource
	lggr logger.Logger
}

// NewStore creates a Store using an existing DataSource.
func NewStore(ds sqlutil.DataSource, lggr logger.Logger) *Store {
	return &Store{ds: ds, lggr: lggr}
}

// NewStoreFromConfig creates a Store with its own Postgres connection pool.
func NewStoreFromConfig(ctx context.Context, lggr logger.Logger, uri string, dbConfig pg.DBConfig) (*Store, error) {
	ds, err := dbConfig.New(ctx, uri, pg.DriverPostgres)
	if err != nil {
		return nil, fmt.Errorf("failed to open replay store connection: %w", err)
	}
	return &Store{ds: ds, lggr: lggr}, nil
}

// DataSource returns the underlying DataSource so the engine can pass it
// to transactional helpers that checkpoint progress alongside data writes.
func (s *Store) DataSource() sqlutil.DataSource {
	return s.ds
}

func (s *Store) CreateJob(ctx context.Context, req Request) (*Job, error) {
	var sinceSeq *int64
	if req.Type == TypeDiscovery {
		v := req.Since
		sinceSeq = &v
	}

	query := `
		INSERT INTO indexer.replay_jobs (type, status, force_overwrite, request_hash, since_sequence_number, message_ids, total_items)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, type, status, force_overwrite, request_hash, since_sequence_number, message_ids,
		          progress_cursor, total_items, processed_items, last_heartbeat,
		          error_message, created_at, updated_at, completed_at
	`

	totalItems := 0
	if req.Type == TypeMessages {
		totalItems = len(req.MessageIDs)
	}

	row, err := s.queryRow(ctx, query,
		string(req.Type),
		string(StatusRunning),
		req.Force,
		req.Hash(),
		sinceSeq,
		pq.Array(req.MessageIDs),
		totalItems,
	)
	if err != nil {
		return nil, err
	}

	return scanJob(row)
}

func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	query := `
		SELECT id, type, status, force_overwrite, request_hash, since_sequence_number, message_ids,
		       progress_cursor, total_items, processed_items, last_heartbeat,
		       error_message, created_at, updated_at, completed_at
		FROM indexer.replay_jobs
		WHERE id = $1
	`
	row, err := s.queryRow(ctx, query, id)
	if err != nil {
		return nil, err
	}
	job, err := scanJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrJobNotFound
		}
		return nil, err
	}
	return job, nil
}

// FindResumable looks for a running job whose heartbeat is stale, meaning the
// previous process crashed. The request_hash ensures that the job's full
// parameter set (type, force flag, since/message_ids) matches the incoming
// retry request exactly, preventing resumption of an unrelated stale job.
func (s *Store) FindResumable(ctx context.Context, req Request) (*Job, error) {
	query := `
		SELECT id, type, status, force_overwrite, request_hash, since_sequence_number, message_ids,
		       progress_cursor, total_items, processed_items, last_heartbeat,
		       error_message, created_at, updated_at, completed_at
		FROM indexer.replay_jobs
		WHERE request_hash = $1 AND status = $2 AND last_heartbeat < $3
		ORDER BY created_at DESC
		LIMIT 1
	`
	row, err := s.queryRow(ctx, query, req.Hash(), string(StatusRunning), time.Now().Add(-StaleJobTimeout))
	if err != nil {
		return nil, err
	}
	job, err := scanJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoResumable
		}
		return nil, err
	}
	return job, nil
}

// AcquireAdvisoryLock pins a dedicated connection from the pool and acquires a
// session-level advisory lock on it. The caller MUST close the returned
// *sql.Conn when done; closing the connection automatically releases the lock.
// Returns ErrJobLocked if the lock is already held by another session.
func (s *Store) AcquireAdvisoryLock(ctx context.Context, jobID string) (*sql.Conn, error) {
	db, ok := s.ds.(interface {
		Conn(context.Context) (*sql.Conn, error)
	})
	if !ok {
		return nil, fmt.Errorf("DataSource does not support pinned connections for advisory locks")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire connection for advisory lock: %w", err)
	}

	var acquired bool
	err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, "replay:"+jobID).Scan(&acquired)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("advisory lock query failed: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		return nil, ErrJobLocked
	}
	return conn, nil
}

// UpdateProgress atomically updates the job's cursor and heartbeat. This should
// be called within the same transaction that persists the replayed data.
func (s *Store) UpdateProgress(ctx context.Context, tx sqlutil.DataSource, jobID string, cursor int64, processedItems int) error {
	query := `
		UPDATE indexer.replay_jobs
		SET progress_cursor = $1, processed_items = $2, last_heartbeat = $3, updated_at = $3
		WHERE id = $4
	`
	now := time.Now()
	_, err := tx.ExecContext(ctx, query, cursor, processedItems, now, jobID)
	if err != nil {
		return fmt.Errorf("failed to update replay progress: %w", err)
	}
	return nil
}

// Heartbeat updates only the heartbeat timestamp without changing progress.
func (s *Store) Heartbeat(ctx context.Context, jobID string) error {
	now := time.Now()
	_, err := s.exec(ctx, `UPDATE indexer.replay_jobs SET last_heartbeat = $1, updated_at = $1 WHERE id = $2`, now, jobID)
	return err
}

func (s *Store) MarkCompleted(ctx context.Context, jobID string) error {
	now := time.Now()
	_, err := s.exec(ctx,
		`UPDATE indexer.replay_jobs SET status = $1, completed_at = $2, updated_at = $2, last_heartbeat = $2 WHERE id = $3`,
		string(StatusCompleted), now, jobID,
	)
	return err
}

func (s *Store) MarkFailed(ctx context.Context, jobID, errMsg string) error {
	now := time.Now()
	_, err := s.exec(ctx,
		`UPDATE indexer.replay_jobs SET status = $1, error_message = $2, updated_at = $3, last_heartbeat = $3 WHERE id = $4`,
		string(StatusFailed), errMsg, now, jobID,
	)
	return err
}

func (s *Store) ListJobs(ctx context.Context) ([]Job, error) {
	query := `
		SELECT id, type, status, force_overwrite, request_hash, since_sequence_number, message_ids,
		       progress_cursor, total_items, processed_items, last_heartbeat,
		       error_message, created_at, updated_at, completed_at
		FROM indexer.replay_jobs
		ORDER BY created_at DESC
		LIMIT 50
	`
	rows, err := s.query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list replay jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []Job
	for rows.Next() {
		job, err := scanJobFromRows(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

func scanJob(row *sql.Row) (*Job, error) {
	var j Job
	var typeStr, statusStr string
	var msgIDs []string

	err := row.Scan(
		&j.ID, &typeStr, &statusStr, &j.ForceOverwrite, &j.RequestHash,
		&j.SinceSequenceNumber, pq.Array(&msgIDs),
		&j.ProgressCursor, &j.TotalItems, &j.ProcessedItems, &j.LastHeartbeat,
		&j.ErrorMessage, &j.CreatedAt, &j.UpdatedAt, &j.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	j.Type = Type(typeStr)
	j.Status = Status(statusStr)
	j.MessageIDs = msgIDs
	return &j, nil
}

func scanJobFromRows(rows *sql.Rows) (*Job, error) {
	var j Job
	var typeStr, statusStr string
	var msgIDs []string

	err := rows.Scan(
		&j.ID, &typeStr, &statusStr, &j.ForceOverwrite, &j.RequestHash,
		&j.SinceSequenceNumber, pq.Array(&msgIDs),
		&j.ProgressCursor, &j.TotalItems, &j.ProcessedItems, &j.LastHeartbeat,
		&j.ErrorMessage, &j.CreatedAt, &j.UpdatedAt, &j.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	j.Type = Type(typeStr)
	j.Status = Status(statusStr)
	j.MessageIDs = msgIDs
	return &j, nil
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) (*sql.Row, error) {
	if querier, ok := s.ds.(interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}); ok {
		return querier.QueryRowContext(ctx, query, args...), nil
	}
	return nil, fmt.Errorf("DataSource does not support QueryRowContext")
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if querier, ok := s.ds.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}); ok {
		return querier.QueryContext(ctx, query, args...)
	}
	return nil, fmt.Errorf("DataSource does not support QueryContext")
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if execer, ok := s.ds.(interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	}); ok {
		return execer.ExecContext(ctx, query, args...)
	}
	return nil, fmt.Errorf("DataSource does not support ExecContext")
}
