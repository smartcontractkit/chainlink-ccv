// Package jobstore provides persistence for job specs received from the Job Distributor.
package jobstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// ErrNoJob is returned when no job is found in the store.
var ErrNoJob = errors.New("no job found in store")

// jobRow is the database row structure for job_store.
type jobRow struct {
	ProposalID string    `db:"proposal_id"`
	Version    int64     `db:"version"`
	Spec       string    `db:"spec"`
	CreatedAt  time.Time `db:"created_at"`
	UpdatedAt  time.Time `db:"updated_at"`
}

// Job represents a persisted job spec from the Job Distributor.
type Job struct {
	ProposalID string
	Version    int64
	Spec       string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Store provides persistence for job specs.
type Store struct {
	ds sqlutil.DataSource
}

// NewStore creates a new job store.
func NewStore(ds sqlutil.DataSource) *Store {
	return &Store{ds: ds}
}

// SaveJob persists a job spec, replacing any existing job.
// Only one job should be active at a time.
func (s *Store) SaveJob(ctx context.Context, proposalID string, version int64, spec string) error {
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
func (s *Store) LoadJob(ctx context.Context) (*Job, error) {
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
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}, nil
}

// HasJob returns true if there is a job in the store.
func (s *Store) HasJob(ctx context.Context) (bool, error) {
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
