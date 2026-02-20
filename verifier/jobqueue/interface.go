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
	JobKey() (chainSelector, messageID string)
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
	// Chain selector for routing and monitoring
	ChainSelector string
	// Message ID for deduplication and tracking
	MessageID string
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
	// Consume retrieves and locks up to batchSize jobs for processing.
	// Jobs are locked for lockDuration to prevent concurrent processing.
	// Returns empty slice if no jobs are available.
	//
	// The implementation should use SELECT FOR UPDATE SKIP LOCKED to ensure
	// concurrent consumers don't compete for the same jobs.
	Consume(ctx context.Context, batchSize int, lockDuration time.Duration) ([]Job[T], error)
	// Complete marks jobs as successfully processed and removes them from active queue.
	// Completed jobs may be moved to an archive table for audit purposes.
	Complete(ctx context.Context, jobIDs ...string) error
	// Retry schedules jobs for retry after the specified delay.
	// Increments attempt count and records the error message.
	// If max attempts is exceeded, jobs are moved to failed status.
	Retry(ctx context.Context, delay time.Duration, errors map[string]error, jobIDs ...string) error
	// Fail marks jobs as permanently failed.
	// These jobs will not be retried and should be investigated.
	Fail(ctx context.Context, errors map[string]error, jobIDs ...string) error
	// Cleanup archives or deletes jobs older than the retention period.
	// Should be called periodically to prevent unbounded table growth.
	Cleanup(ctx context.Context, retentionPeriod time.Duration) (int, error)
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
}
