// Package store provides persistence for job specs received from the Job Distributor.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// ErrNoJob is returned when no job is found in the store.
var ErrNoJob = errors.New("no job found in store")

// StoreInterface defines the interface for persisting job specs.
// It can, in theory, be implemented using any storage backend.
type StoreInterface interface {
	// SaveJob persists a job spec to the persistent store.
	SaveJob(ctx context.Context, proposalID string, version int64, spec string) error
	// LoadJob loads the most recent job spec from the persistent store.
	LoadJob(ctx context.Context) (*Job, error)
	// DeleteJob deletes all job specs from the persistent store.
	DeleteJob(ctx context.Context) error
}

// Ensure PGStore implements StoreInterface.
var _ StoreInterface = (*PGStore)(nil)

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

// PGStore provides persistence for job specs using Postgres.
type PGStore struct {
	ds sqlutil.DataSource
}

// NewPGStore creates a new job store using Postgres.
func NewPGStore(ds sqlutil.DataSource) *PGStore {
	return &PGStore{ds: ds}
}

// SaveJob persists a job spec, replacing any existing job.
// Only one job should be active at a time.
func (s *PGStore) SaveJob(ctx context.Context, proposalID string, version int64, spec string) error {
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
func (s *PGStore) LoadJob(ctx context.Context) (*Job, error) {
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

// DeleteJob removes the persisted job from the store.
func (s *PGStore) DeleteJob(ctx context.Context) error {
	_, err := s.ds.ExecContext(ctx, `DELETE FROM job_store`)
	if err != nil {
		return fmt.Errorf("failed to delete job: %w", err)
	}
	return nil
}
