package jobqueue

import (
	"context"
	"time"
)

// JobStatus represents the current state of a job in the queue.
type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusProcessing JobStatus = "processing"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
)

// Jobable is the interface that job payloads must implement to be stored in the queue.
// It provides chain selector and message ID for database indexing and querying.
type Jobable interface {
	// JobKey returns the chain selector and message ID for this job.
	// These are used for database indexing, querying, and job routing.
	// chainSelector is a uint64 representing the chain
	// messageID is a byte slice representing the unique message identifier.
	JobKey() (chainSelector uint64, messageID []byte)
}

// Job wraps a payload with queue metadata.
type Job[T Jobable] struct {
	// Unique job identifier
	ID string
	// The actual payload to process
	Payload T
	// Number of times this job has been attempted
	AttemptCount int
	// Deadline after which retries are no longer allowed
	RetryDeadline time.Time
	// When the job was created
	CreatedAt time.Time
	// When processing started (nil if not started)
	StartedAt *time.Time
	// Chain selector for routing and monitoring (uint64)
	ChainSelector uint64
	// Message ID for deduplication and tracking (byte slice)
	MessageID []byte
}

// JobQueue defines a generic durable queue interface backed by persistent storage.
// The queue supports delayed retry, dead letter handling, and concurrent processing.
// Type T must implement Jobable to provide chain selector and message ID.
type JobQueue[T Jobable] interface {
	// Publish adds one or more jobs to the queue.
	// Jobs are immediately available for consumption unless a delay is specified.
	Publish(ctx context.Context, jobs ...T) error
	// PublishWithDelay adds jobs that become available after the specified delay.
	// Useful for implementing retry backoff strategies.
	PublishWithDelay(ctx context.Context, delay time.Duration, jobs ...T) error
	// ConsumePending retrieves and locks up to batchSize jobs that are available now.
	// It does not reclaim stale jobs.
	//
	// A consumer that waits on Signals uses this together with ReclaimStale, so the two
	// halves run on schedules that suit them: pending work is announced by a signal,
	// while stale work is only produced by the passage of time.
	ConsumePending(ctx context.Context, batchSize int) ([]Job[T], error)
	// ReclaimStale retrieves and locks up to batchSize jobs that have been in
	// 'processing' for longer than the configured LockDuration.
	//
	// No signal can announce stale work, so a consumer must drive this from a timer.
	ReclaimStale(ctx context.Context, batchSize int) ([]Job[T], error)
	// Signals reports newly available work, so a consumer can wait instead of polling.
	//
	// The signal is a hint, never a record. Every row stays reachable by ConsumePending,
	// so a signal that is never delivered costs latency and never costs a job. A consumer
	// must therefore keep a slow fallback poll: work can also become available without any
	// signal, from a republish that ON CONFLICT DO NOTHING drops after a restart, from the
	// out-of-process job queue CLI, or from another process sharing the same owner_id.
	//
	// Signals coalesce, so one wakeup can stand for any amount of work. A consumer must
	// look again whenever its last look returned anything.
	Signals() <-chan struct{}
	// Complete marks jobs as successfully processed and removes them from active queue.
	// Completed jobs may be moved to an archive table for audit purposes.
	Complete(ctx context.Context, jobIDs ...string) error
	// Retry schedules jobs for retry after the specified delay.
	// Increments attempt count and records the error message.
	// If the retry deadline has been exceeded, jobs are marked as failed and archived.
	Retry(ctx context.Context, delay time.Duration, errors map[string]error, jobIDs ...string) error
	// Fail marks jobs as permanently failed and moves them to the archive.
	// These jobs will not be retried and should be investigated via the archive table.
	Fail(ctx context.Context, errors map[string]error, jobIDs ...string) error
	// Cleanup archives or deletes jobs older than the retention period.
	// Should be called periodically to prevent unbounded table growth.
	Cleanup(ctx context.Context, retentionPeriod time.Duration) (int, error)
	// Size returns the count of jobs that are pending or processing.
	// This is useful for monitoring queue health and capacity.
	// Failed jobs and archived jobs are excluded from the count.
	Size(ctx context.Context) (int, error)
	// Name returns the queue name for logging and monitoring
	Name() string
}

// QueueConfig contains configuration for queue behavior.
type QueueConfig struct {
	// Queue name for logging and table naming
	Name string
	// OwnerID scopes jobs so multiple verifiers sharing the same table
	// only consume their own jobs (e.g. "CCTPVerifier", "LombardVerifier").
	OwnerID string
	// RetryDuration is how long from creation a job is eligible for retry.
	// After this duration elapses, a failed retry marks the job as permanently failed.
	RetryDuration time.Duration
	// LockDuration is how long a job can remain in 'processing' before it is
	// considered stale and automatically reclaimed by the next Consume call.
	LockDuration time.Duration
}
