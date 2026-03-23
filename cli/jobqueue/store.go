package jobqueue

import (
	"context"
	"time"
)

// QueueType identifies which verifier processing queue to operate on.
type QueueType string

const (
	// QueueTypeTaskVerifier is the task-verifier queue (first pipeline stage).
	QueueTypeTaskVerifier QueueType = "task-verifier"
	// QueueTypeStorageWriter is the storage-writer queue (second pipeline stage).
	QueueTypeStorageWriter QueueType = "storage-writer"
)

// ArchivedJob represents a failed job from the archive table.
type ArchivedJob struct {
	// JobID is the UUID of the job.
	JobID string
	// MessageID is the raw message identifier bytes.
	MessageID []byte
	// OwnerID scopes the job to a particular verifier instance.
	OwnerID string
	// ChainSelector is the source chain selector.
	ChainSelector uint64
	// Status is the job status at archive time (always "failed" for retryable jobs).
	Status string
	// AttemptCount is the number of times the job was attempted before archiving.
	AttemptCount int
	// LastError is the last error message recorded before archiving.
	LastError string
	// CreatedAt is when the job was originally created.
	CreatedAt time.Time
	// ArchivedAt is when the job was moved to the archive.
	ArchivedAt *time.Time
	// RetryDeadline is the original retry deadline (now exceeded for failed jobs).
	RetryDeadline time.Time
	// Queue is the queue this job belongs to.
	Queue QueueType
}

// Store is the minimal database interface required by the jobqueue CLI commands.
type Store interface {
	// ListFailed returns failed jobs from the archive table(s).
	// Pass an empty queues slice to list from both queues.
	// Pass an empty ownerID to list across all verifier IDs.
	ListFailed(ctx context.Context, queues []QueueType, ownerID string, limit int) ([]ArchivedJob, error)

	// RescheduleByJobID moves a failed job from the archive back to the active table,
	// giving it a fresh retry window of retryDuration from now.
	RescheduleByJobID(ctx context.Context, queue QueueType, ownerID, jobID string, retryDuration time.Duration) error

	// RescheduleByMessageID moves a failed job from the archive back to the active table
	// by its raw message ID bytes, giving it a fresh retry window of retryDuration from now.
	RescheduleByMessageID(ctx context.Context, queue QueueType, ownerID string, messageID []byte, retryDuration time.Duration) error
}
