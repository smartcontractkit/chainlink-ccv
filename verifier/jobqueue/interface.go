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

// Job wraps a payload with queue metadata.
type Job[T any] struct {
	// Unique job identifier
	ID string

	// The actual payload to process
	Payload T

	// Number of times this job has been attempted
	AttemptCount int

	// Maximum number of attempts allowed
	MaxAttempts int

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
type JobQueue[T any] interface {
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

	// Default maximum attempts before job is failed
	DefaultMaxAttempts int

	// Default lock duration for consumed jobs
	DefaultLockDuration time.Duration

	// Batch size for consumption
	DefaultBatchSize int

	// How often to poll for new jobs
	PollInterval time.Duration

	// Retention period for completed jobs
	RetentionPeriod time.Duration
}

// DefaultQueueConfig returns sensible defaults.
func DefaultQueueConfig(name string) QueueConfig {
	return QueueConfig{
		Name:                name,
		DefaultMaxAttempts:  5,
		DefaultLockDuration: 5 * time.Minute,
		DefaultBatchSize:    20,
		PollInterval:        100 * time.Millisecond,
		RetentionPeriod:     7 * 24 * time.Hour, // 7 days
	}
}
