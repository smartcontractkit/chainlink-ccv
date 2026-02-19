package jobqueue

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJobQueue provides test utilities for job queue testing.
type TestJobQueue[T Jobable] struct {
	jobs      []Job[T]
	completed []string
	failed    []string
	retried   map[string]int
}

func NewTestJobQueue[T Jobable]() *TestJobQueue[T] {
	return &TestJobQueue[T]{
		jobs:    make([]Job[T], 0),
		retried: make(map[string]int),
	}
}

func (q *TestJobQueue[T]) Publish(ctx context.Context, jobs ...T) error {
	return q.PublishWithDelay(ctx, 0, jobs...)
}

func (q *TestJobQueue[T]) PublishWithDelay(ctx context.Context, delay time.Duration, jobs ...T) error {
	for _, job := range jobs {
		q.jobs = append(q.jobs, Job[T]{
			ID:           generateID(),
			Payload:      job,
			AttemptCount: 0,
			MaxAttempts:  5,
			CreatedAt:    time.Now(),
		})
	}
	return nil
}

func (q *TestJobQueue[T]) Consume(ctx context.Context, batchSize int, lockDuration time.Duration) ([]Job[T], error) {
	var result []Job[T]
	for i := 0; i < len(q.jobs) && len(result) < batchSize; i++ {
		if !slices.Contains(q.completed, q.jobs[i].ID) && !slices.Contains(q.failed, q.jobs[i].ID) {
			q.jobs[i].AttemptCount++
			now := time.Now()
			q.jobs[i].StartedAt = &now
			result = append(result, q.jobs[i])
		}
	}
	return result, nil
}

func (q *TestJobQueue[T]) Complete(ctx context.Context, jobIDs ...string) error {
	q.completed = append(q.completed, jobIDs...)
	return nil
}

func (q *TestJobQueue[T]) Retry(ctx context.Context, delay time.Duration, errors map[string]error, jobIDs ...string) error {
	for _, id := range jobIDs {
		q.retried[id]++
	}
	return nil
}

func (q *TestJobQueue[T]) Fail(ctx context.Context, errors map[string]error, jobIDs ...string) error {
	q.failed = append(q.failed, jobIDs...)
	return nil
}

func (q *TestJobQueue[T]) Cleanup(ctx context.Context, retentionPeriod time.Duration) (int, error) {
	return 0, nil
}

func (q *TestJobQueue[T]) Name() string {
	return "test-queue"
}

// Test helper functions.
var idCounter = 0

func generateID() string {
	idCounter++
	return string(rune('A' + idCounter))
}

// Example test structure.
type TestPayload struct {
	Value string
}

// JobKey implements the Jobable interface.
func (t TestPayload) JobKey() (chainSelector, messageID string) {
	return "test-chain", t.Value
}

func TestJobQueueInterface(t *testing.T) {
	ctx := context.Background()
	queue := NewTestJobQueue[TestPayload]()

	t.Run("Publish and Consume", func(t *testing.T) {
		// Publish jobs
		err := queue.Publish(ctx,
			TestPayload{Value: "job1"},
			TestPayload{Value: "job2"},
		)
		require.NoError(t, err)

		// Consume jobs
		jobs, err := queue.Consume(ctx, 10, 5*time.Minute)
		require.NoError(t, err)
		assert.Len(t, jobs, 2)
	})

	t.Run("Complete jobs", func(t *testing.T) {
		jobs, _ := queue.Consume(ctx, 10, 5*time.Minute)
		require.NotEmpty(t, jobs)

		// Complete first job
		err := queue.Complete(ctx, jobs[0].ID)
		require.NoError(t, err)
	})

	t.Run("Retry jobs", func(t *testing.T) {
		jobs, _ := queue.Consume(ctx, 10, 5*time.Minute)
		require.NotEmpty(t, jobs)

		// Retry with error
		errors := map[string]error{
			jobs[0].ID: assert.AnError,
		}
		err := queue.Retry(ctx, 1*time.Second, errors, jobs[0].ID)
		require.NoError(t, err)
		assert.Equal(t, 1, queue.retried[jobs[0].ID])
	})

	t.Run("Fail jobs", func(t *testing.T) {
		jobs, _ := queue.Consume(ctx, 10, 5*time.Minute)
		require.NotEmpty(t, jobs)

		errors := map[string]error{
			jobs[0].ID: assert.AnError,
		}
		err := queue.Fail(ctx, errors, jobs[0].ID)
		require.NoError(t, err)
	})
}
