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
type StoreInterface interface {
	// SaveJob persists a new proposal as pending, replacing any existing record.
	SaveJob(ctx context.Context, proposalID string, version int64, spec string) error
	// MarkJobApproved transitions the stored record from pending to approved.
	MarkJobApproved(ctx context.Context) error
	// LoadJob returns the current job record, or ErrNoJob if none exists.
	LoadJob(ctx context.Context) (*Job, error)
	// DeleteJob removes the persisted record.
	DeleteJob(ctx context.Context) error
}
