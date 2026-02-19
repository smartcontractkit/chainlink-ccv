package store

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// jobRow is the database row structure for job_store.
type jobRow struct {
	ProposalID string    `db:"proposal_id"`
	Version    int64     `db:"version"`
	Spec       string    `db:"spec"`
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
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
*/
func NewPostgresStore(ds sqlutil.DataSource) *PostgresStore {
	return &PostgresStore{ds: ds}
}

// SaveJob persists a job spec, replacing any existing job.
// Only one job should be active at a time.
func (s *PostgresStore) SaveJob(ctx context.Context, proposalID string, version int64, spec string) error {
	// Delete any existing jobs first (we only keep one)
	_, err := s.ds.ExecContext(ctx, `DELETE FROM job_store`)
	if err != nil {
		return fmt.Errorf("failed to clear existing jobs: %w", err)
	}

	// Insert the new job
	_, err = s.ds.ExecContext(ctx,
		`INSERT INTO job_store (proposal_id, version, spec, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())`,
		proposalID, version, spec,
	)
	if err != nil {
		return fmt.Errorf("failed to save job: %w", err)
	}

	return nil
}

// LoadJob retrieves the current job spec from the store.
// Returns ErrNoJob if no job is found.
func (s *PostgresStore) LoadJob(ctx context.Context) (*Job, error) {
	var rows []jobRow
	err := s.ds.SelectContext(ctx, &rows,
		`SELECT proposal_id, version, spec, created_at, updated_at FROM job_store ORDER BY id DESC LIMIT 1`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load job: %w", err)
	}

	if len(rows) == 0 {
		return nil, ErrNoJob
	}

	row := rows[0]
	return &Job{
		ProposalID: row.ProposalID,
		Version:    row.Version,
		Spec:       row.Spec,
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

// DeleteJob removes the persisted job from the store.
// This is called when JD sends a delete request.
func (s *PostgresStore) DeleteJob(ctx context.Context) error {
	_, err := s.ds.ExecContext(ctx, `DELETE FROM job_store`)
	if err != nil {
		return fmt.Errorf("failed to delete job: %w", err)
	}
	return nil
}
