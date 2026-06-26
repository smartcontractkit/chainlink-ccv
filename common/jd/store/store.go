package store

import (
	"context"
	"errors"
)

// ErrNoJob is returned by LoadJob when no job is found in the store.
var ErrNoJob = errors.New("no job found")

// JobStatus represents the persistence state of a job proposal.
type JobStatus string

const (
	// JobStatusPending means the proposal was saved but StartJob has not succeeded yet.
	JobStatusPending JobStatus = "pending"
	// JobStatusApproved means the job was started and approved successfully.
	JobStatusApproved JobStatus = "approved"
)

// Job holds the persisted state of a job proposal.
type Job struct {
	ProposalID string
	Version    int64
	Spec       string
	Status     JobStatus
}

// StoreInterface defines the persistence contract for job proposals.
//
//revive:disable-next-line:exported
type StoreInterface interface {
	// SavePendingJob persists a new proposal as pending.
	// Any existing pending row is replaced; any existing approved row is preserved.
	SavePendingJob(ctx context.Context, proposalID string, version int64, spec string) error
	// AcceptPendingJob promotes the pending record to approved, replacing any old approved record.
	// Returns true if a pending record was found and promoted, false if there was nothing to promote.
	AcceptPendingJob(ctx context.Context) (bool, error)
	// LoadJob returns the current job record, or ErrNoJob if none exists.
	// When both an approved and a pending row exist, the approved row is returned.
	LoadJob(ctx context.Context) (*Job, error)
	// DeleteAllJobs removes all persisted records.
	DeleteAllJobs(ctx context.Context) error
	// DeletePendingJob removes only the pending record, leaving any approved record intact.
	// Used to rollback a failed replacement proposal.
	DeletePendingJob(ctx context.Context) error
}
