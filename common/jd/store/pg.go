package store

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// Ensure PostgresStore implements StoreInterface.
var _ StoreInterface = (*PostgresStore)(nil)

// jobRow is the database row structure for job_store.
type jobRow struct {
	ProposalID string    `db:"proposal_id"`
	Version    int64     `db:"version"`
	Spec       string    `db:"spec"`
	Status     string    `db:"status"`
	CreatedAt  time.Time `db:"created_at"`
	UpdatedAt  time.Time `db:"updated_at"`
}

// PostgresStore provides persistence for job specs through postgres.
type PostgresStore struct {
	ds sqlutil.DataSource
}

// NewPostgresStore creates a new job store backed by postgres.
// The table is expected to be the following:
/*
	CREATE TABLE IF NOT EXISTS job_store (
		id SERIAL PRIMARY KEY,
		proposal_id TEXT NOT NULL,
		version BIGINT NOT NULL,
		spec TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'approved' CHECK (status IN ('pending', 'approved')),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		CONSTRAINT job_store_unique_status UNIQUE (status)
	);
*/
func NewPostgresStore(ds sqlutil.DataSource) *PostgresStore {
	return &PostgresStore{ds: ds}
}

// SavePendingJob persists a new proposal as pending.
// Any existing pending row is replaced via ON CONFLICT; any existing approved row is preserved
// so that a failed replacement can fall back to the old job on restart.
func (s *PostgresStore) SavePendingJob(ctx context.Context, proposalID string, version int64, spec string) error {
	_, err := s.ds.ExecContext(ctx,
		`INSERT INTO job_store (proposal_id, version, spec, status, created_at, updated_at)
		 VALUES ($1, $2, $3, 'pending', NOW(), NOW())
		 ON CONFLICT (status) DO UPDATE SET
		     proposal_id = EXCLUDED.proposal_id,
		     version     = EXCLUDED.version,
		     spec        = EXCLUDED.spec,
		     updated_at  = NOW()
		 WHERE job_store.status = 'pending'`,
		proposalID, version, spec,
	)
	if err != nil {
		return fmt.Errorf("failed to save pending job: %w", err)
	}
	return nil
}

// AcceptPendingJob promotes the pending record to approved, replacing any old approved record.
// Returns true if a pending record was promoted, false if none existed.
// The DELETE and UPDATE run in a transaction so that a failure on the UPDATE rolls back the
// DELETE — preventing the approved row from being silently lost.
// A data-modifying CTE cannot be used instead because PostgreSQL CTEs share the same snapshot,
// causing the UPDATE to see the approved row as still present and violate UNIQUE(status).
func (s *PostgresStore) AcceptPendingJob(ctx context.Context) (bool, error) {
	var promoted bool
	err := sqlutil.TransactDataSource(ctx, s.ds, nil, func(tx sqlutil.DataSource) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM job_store WHERE status = 'approved'`)
		if err != nil {
			return fmt.Errorf("failed to remove old approved job: %w", err)
		}

		result, err := tx.ExecContext(ctx,
			`UPDATE job_store SET status = 'approved', updated_at = NOW() WHERE status = 'pending'`,
		)
		if err != nil {
			return fmt.Errorf("failed to accept pending job: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		promoted = rows > 0
		return nil
	})
	return promoted, err
}

// LoadJob retrieves the active job from the store.
// When both an approved and a pending row exist (failed replacement), the approved row
// is returned so the known-good job starts on restart.
// Returns ErrNoJob if no job is found.
func (s *PostgresStore) LoadJob(ctx context.Context) (*Job, error) {
	var rows []jobRow
	err := s.ds.SelectContext(ctx, &rows,
		`SELECT proposal_id, version, spec, status, created_at, updated_at
		 FROM job_store
		 ORDER BY (status = 'approved') DESC, id DESC
		 LIMIT 1`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load job: %w", err)
	}

	if len(rows) == 0 {
		return nil, ErrNoJob
	}

	row := rows[0]
	status := JobStatus(row.Status)
	if status == "" {
		status = JobStatusApproved
	}
	return &Job{
		ProposalID: row.ProposalID,
		Version:    row.Version,
		Spec:       row.Spec,
		Status:     status,
	}, nil
}

// HasJob returns true if there is a job in the store.
func (s *PostgresStore) HasJob(ctx context.Context) (bool, error) {
	var counts []int
	err := s.ds.SelectContext(ctx, &counts, `SELECT COUNT(*) FROM job_store`)
	if err != nil {
		return false, fmt.Errorf("failed to check for job: %w", err)
	}
	if len(counts) == 0 {
		return false, nil
	}
	return counts[0] > 0, nil
}

// DeleteAllJobs removes all persisted job records.
// Called when JD sends a delete request.
func (s *PostgresStore) DeleteAllJobs(ctx context.Context) error {
	_, err := s.ds.ExecContext(ctx, `DELETE FROM job_store`)
	if err != nil {
		return fmt.Errorf("failed to delete jobs: %w", err)
	}
	return nil
}

// DeletePendingJob removes only the pending record, leaving any approved record intact.
// Called to rollback a failed replacement proposal.
func (s *PostgresStore) DeletePendingJob(ctx context.Context) error {
	_, err := s.ds.ExecContext(ctx, `DELETE FROM job_store WHERE status = 'pending'`)
	if err != nil {
		return fmt.Errorf("failed to delete pending job: %w", err)
	}
	return nil
}
