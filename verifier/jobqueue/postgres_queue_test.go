package jobqueue_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// testJob implements Jobable for testing purposes.
type testJob struct {
	Chain   string `json:"chain"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (j testJob) JobKey() (chainSelector, messageID string) {
	return j.Chain, j.Message
}

// newTestQueue creates a PostgresJobQueue[testJob] backed by a real Postgres testcontainer.
// It uses the "verification_tasks" table which is created by migrations.
func newTestQueue(t *testing.T, opts ...func(*jobqueue.QueueConfig)) (*jobqueue.PostgresJobQueue[testJob], *sql.DB) {
	t.Helper()

	ds := testutil.NewTestDB(t)
	db := ds.(*sqlx.DB).DB

	cfg := jobqueue.QueueConfig{
		Name:               "verification_tasks",
		DefaultMaxAttempts: 3,
	}
	for _, o := range opts {
		o(&cfg)
	}

	q, err := jobqueue.NewPostgresJobQueue[testJob](db, cfg, logger.Test(t))
	require.NoError(t, err)
	return q, db
}

// countRows is a test helper that counts rows in a table with a given status filter.
func countRows(t *testing.T, db *sql.DB, table string, status jobqueue.JobStatus) int {
	t.Helper()
	var count int
	//nolint:gosec // test-only helper
	err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE status = $1", table), string(status)).Scan(&count)
	require.NoError(t, err)
	return count
}

// countAllRows is a test helper that counts all rows in a table.
func countAllRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	//nolint:gosec // test-only helper
	err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
	require.NoError(t, err)
	return count
}

func TestPublishAndConsume(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	jobs := []testJob{
		{Chain: "1", Message: "msg-1", Data: "payload-1"},
		{Chain: "1", Message: "msg-2", Data: "payload-2"},
		{Chain: "2", Message: "msg-3", Data: "payload-3"},
	}

	// Publish
	require.NoError(t, q.Publish(ctx, jobs...))

	// Consume all
	consumed, err := q.Consume(ctx, 10, 5*time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 3)

	// Verify payload round-trip
	payloads := map[string]testJob{}
	for _, j := range consumed {
		payloads[j.Payload.Message] = j.Payload
		assert.Equal(t, j.Payload.Chain, j.ChainSelector)
		assert.Equal(t, j.Payload.Message, j.MessageID)
		assert.Equal(t, 1, j.AttemptCount)
		assert.Equal(t, 3, j.MaxAttempts)
		assert.NotNil(t, j.StartedAt)
	}
	assert.Equal(t, "payload-1", payloads["msg-1"].Data)
	assert.Equal(t, "payload-2", payloads["msg-2"].Data)
	assert.Equal(t, "payload-3", payloads["msg-3"].Data)
}

func TestPublishEmpty(t *testing.T) {
	q, _ := newTestQueue(t)
	require.NoError(t, q.Publish(context.Background()))
}

func TestConsumeEmpty(t *testing.T) {
	q, _ := newTestQueue(t)
	consumed, err := q.Consume(context.Background(), 10, time.Minute)
	require.NoError(t, err)
	assert.Empty(t, consumed)
}

func TestConsumeRespectsAvailableAt(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	// Publish with a 1-hour delay – should NOT be consumable now
	require.NoError(t, q.PublishWithDelay(ctx, time.Hour, testJob{Chain: "1", Message: "delayed", Data: "d"}))

	consumed, err := q.Consume(ctx, 10, time.Minute)
	require.NoError(t, err)
	assert.Empty(t, consumed)
}

func TestConsumeBatchSizeLimit(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: fmt.Sprintf("m-%d", i), Data: "x"}))
	}

	consumed, err := q.Consume(ctx, 2, time.Minute)
	require.NoError(t, err)
	assert.Len(t, consumed, 2)
}

func TestConsumeDoesNotReturnProcessingJobs(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))

	// First consume locks the job
	first, err := q.Consume(ctx, 10, time.Minute)
	require.NoError(t, err)
	require.Len(t, first, 1)

	// Second consume should return nothing – job is processing
	second, err := q.Consume(ctx, 10, time.Minute)
	require.NoError(t, err)
	assert.Empty(t, second)
}

func TestComplete(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))

	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)

	// Complete the job
	require.NoError(t, q.Complete(ctx, consumed[0].ID))

	// Main table should be empty, archive should have 1
	assert.Equal(t, 0, countAllRows(t, db, "verification_tasks"))
	assert.Equal(t, 1, countAllRows(t, db, "verification_tasks_archive"))
}

func TestCompleteEmpty(t *testing.T) {
	q, _ := newTestQueue(t)
	require.NoError(t, q.Complete(context.Background()))
}

func TestCompleteNonExistentJob(t *testing.T) {
	q, db := newTestQueue(t)
	// Completing a non-existent job should not error, just affect 0 rows
	require.NoError(t, q.Complete(context.Background(), "00000000-0000-0000-0000-000000000000"))
	assert.Equal(t, 0, countAllRows(t, db, "verification_tasks_archive"))
}

func TestRetry(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))

	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID

	// Retry with an error message
	errs := map[string]error{jobID: errors.New("transient failure")}
	require.NoError(t, q.Retry(ctx, 0, errs, jobID))

	// Job should be back to pending (attempt_count=1 < max_attempts=3)
	assert.Equal(t, 1, countRows(t, db, "verification_tasks", jobqueue.JobStatusPending))

	// Consume again (attempt 2)
	consumed2, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed2, 1)
	assert.Equal(t, 2, consumed2[0].AttemptCount)
}

func TestRetryExceedsMaxAttempts(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.DefaultMaxAttempts = 1 // fail after 1 attempt
	})
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))

	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID
	// attempt_count is now 1, max_attempts is 1

	errs := map[string]error{jobID: errors.New("fatal")}
	require.NoError(t, q.Retry(ctx, 0, errs, jobID))

	// Job should be marked as failed because attempt_count >= max_attempts
	assert.Equal(t, 1, countRows(t, db, "verification_tasks", jobqueue.JobStatusFailed))
	assert.Equal(t, 0, countRows(t, db, "verification_tasks", jobqueue.JobStatusPending))
}

func TestRetryWithDelay(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))

	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)

	// Retry with 1-hour delay
	errs := map[string]error{consumed[0].ID: errors.New("oops")}
	require.NoError(t, q.Retry(ctx, time.Hour, errs, consumed[0].ID))

	// Job is pending but available_at is in the future → not consumable
	second, err := q.Consume(ctx, 10, time.Minute)
	require.NoError(t, err)
	assert.Empty(t, second)
}

func TestFail(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))

	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID

	errs := map[string]error{jobID: errors.New("permanent")}
	require.NoError(t, q.Fail(ctx, errs, jobID))

	assert.Equal(t, 1, countRows(t, db, "verification_tasks", jobqueue.JobStatusFailed))

	// Verify error is stored
	var lastErr string
	err = db.QueryRow("SELECT last_error FROM verification_tasks WHERE job_id = $1", jobID).Scan(&lastErr)
	require.NoError(t, err)
	assert.Equal(t, "permanent", lastErr)
}

// Failed jobs are re-consumable by the Consume query (status IN ('pending','failed'))
func TestFailedJobsAreReconsumed(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))

	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)

	// Mark as failed
	require.NoError(t, q.Fail(ctx, map[string]error{consumed[0].ID: errors.New("err")}, consumed[0].ID))

	// Should be consumable again
	consumed2, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed2, 1)
	assert.Equal(t, consumed[0].ID, consumed2[0].ID)
}

func TestCleanup(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	// Publish, consume, and complete a job so it lands in the archive
	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))
	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	require.NoError(t, q.Complete(ctx, consumed[0].ID))

	assert.Equal(t, 1, countAllRows(t, db, "verification_tasks_archive"))

	// Back-date the completed_at so cleanup will pick it up
	_, err = db.Exec("UPDATE verification_tasks_archive SET completed_at = NOW() - INTERVAL '2 hours'")
	require.NoError(t, err)

	deleted, err := q.Cleanup(ctx, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
	assert.Equal(t, 0, countAllRows(t, db, "verification_tasks_archive"))
}

func TestCleanupRetainsRecentJobs(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "m1", Data: "x"}))
	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.NoError(t, q.Complete(ctx, consumed[0].ID))

	// Cleanup with very long retention – nothing should be deleted
	deleted, err := q.Cleanup(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
	assert.Equal(t, 1, countAllRows(t, db, "verification_tasks_archive"))
}

func TestFullLifecycle(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	// 1. Publish
	require.NoError(t, q.Publish(ctx, testJob{Chain: "42", Message: "lifecycle-1", Data: "step1"}))

	// 2. Consume (attempt 1)
	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID
	assert.Equal(t, 1, consumed[0].AttemptCount)

	// 3. Retry (simulate transient failure)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("timeout")}, jobID))

	// 4. Consume (attempt 2)
	consumed2, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed2, 1)
	assert.Equal(t, jobID, consumed2[0].ID)
	assert.Equal(t, 2, consumed2[0].AttemptCount)

	// 5. Complete
	require.NoError(t, q.Complete(ctx, jobID))
	assert.Equal(t, 0, countAllRows(t, db, "verification_tasks"))
	assert.Equal(t, 1, countAllRows(t, db, "verification_tasks_archive"))

	// 6. Back-date and cleanup
	_, err = db.Exec("UPDATE verification_tasks_archive SET completed_at = NOW() - INTERVAL '48 hours'")
	require.NoError(t, err)
	deleted, err := q.Cleanup(ctx, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
}

func TestConcurrentPublishAndConsume(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	const (
		numProducers    = 5
		jobsPerProducer = 20
		totalJobs       = numProducers * jobsPerProducer
		numConsumers    = 4
		batchSize       = 7
	)

	// --- Producers ---
	var wgPub sync.WaitGroup
	wgPub.Add(numProducers)
	for p := 0; p < numProducers; p++ {
		go func(producerID int) {
			defer wgPub.Done()
			for j := 0; j < jobsPerProducer; j++ {
				job := testJob{
					Chain:   fmt.Sprintf("chain-%d", producerID),
					Message: fmt.Sprintf("msg-%d-%d", producerID, j),
					Data:    fmt.Sprintf("data-%d-%d", producerID, j),
				}
				// Random sleep to simulate realistic timing
				time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond) //nolint:gosec
				err := q.Publish(ctx, job)
				assert.NoError(t, err)
			}
		}(p)
	}
	wgPub.Wait()

	// --- Consumers ---
	var (
		consumed atomic.Int64
		seen     sync.Map // track job IDs to detect duplicates
	)

	var wgCon sync.WaitGroup
	wgCon.Add(numConsumers)
	for c := 0; c < numConsumers; c++ {
		go func() {
			defer wgCon.Done()
			for {
				// Random sleep to simulate work
				time.Sleep(time.Duration(rand.Intn(3)) * time.Millisecond) //nolint:gosec
				batch, err := q.Consume(ctx, batchSize, time.Minute)
				if err != nil {
					t.Errorf("consume error: %v", err)
					return
				}
				if len(batch) == 0 {
					// Check if we're done
					if consumed.Load() >= totalJobs {
						return
					}
					// Might need to wait for more
					time.Sleep(10 * time.Millisecond)
					if consumed.Load() >= totalJobs {
						return
					}
					continue
				}
				for _, j := range batch {
					if _, loaded := seen.LoadOrStore(j.ID, true); loaded {
						t.Errorf("duplicate job consumed: %s", j.ID)
					}
					consumed.Add(1)
				}
				// Complete the batch
				ids := make([]string, len(batch))
				for i, j := range batch {
					ids[i] = j.ID
				}
				err = q.Complete(ctx, ids...)
				assert.NoError(t, err)
			}
		}()
	}
	wgCon.Wait()

	assert.Equal(t, int64(totalJobs), consumed.Load())
	assert.Equal(t, 0, countAllRows(t, db, "verification_tasks"))
	assert.Equal(t, totalJobs, countAllRows(t, db, "verification_tasks_archive"))
}

func TestConcurrentConsumersNoDuplicates(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	const numJobs = 50
	for i := 0; i < numJobs; i++ {
		require.NoError(t, q.Publish(ctx, testJob{
			Chain:   "1",
			Message: fmt.Sprintf("dup-test-%d", i),
			Data:    "x",
		}))
	}

	var (
		seen sync.Map
		wg   sync.WaitGroup
	)
	numConsumers := 8
	wg.Add(numConsumers)
	for c := 0; c < numConsumers; c++ {
		go func() {
			defer wg.Done()
			for {
				batch, err := q.Consume(ctx, 3, time.Minute)
				if err != nil {
					return
				}
				if len(batch) == 0 {
					return
				}
				for _, j := range batch {
					if _, loaded := seen.LoadOrStore(j.ID, true); loaded {
						t.Errorf("duplicate job ID consumed: %s", j.ID)
					}
				}
				ids := make([]string, len(batch))
				for i, j := range batch {
					ids[i] = j.ID
				}
				_ = q.Complete(ctx, ids...)
			}
		}()
	}
	wg.Wait()

	// Count unique seen jobs
	var count int
	seen.Range(func(_, _ any) bool { count++; return true })
	assert.Equal(t, numJobs, count)
}

func TestConcurrentRetryAndFail(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.DefaultMaxAttempts = 5
	})
	ctx := context.Background()

	const numJobs = 30

	for i := 0; i < numJobs; i++ {
		require.NoError(t, q.Publish(ctx, testJob{
			Chain:   "chain-1",
			Message: fmt.Sprintf("rf-%d", i),
			Data:    fmt.Sprintf("val-%d", i),
		}))
	}

	var (
		completed atomic.Int64
		failed    atomic.Int64
		wg        sync.WaitGroup
	)

	numWorkers := 4
	wg.Add(numWorkers)
	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(workerID))) //nolint:gosec

			for {
				batch, err := q.Consume(ctx, 5, time.Minute)
				if err != nil {
					return
				}
				if len(batch) == 0 {
					// Give retried jobs time to become available
					time.Sleep(20 * time.Millisecond)
					batch, err = q.Consume(ctx, 5, time.Minute)
					if err != nil || len(batch) == 0 {
						return
					}
				}

				for _, j := range batch {
					// Simulate random work
					time.Sleep(time.Duration(rng.Intn(5)) * time.Millisecond)

					outcome := rng.Intn(3) // 0=complete, 1=retry, 2=fail
					switch outcome {
					case 0:
						// Success
						err := q.Complete(ctx, j.ID)
						assert.NoError(t, err)
						completed.Add(1)
					case 1:
						// Transient error → retry
						errs := map[string]error{j.ID: fmt.Errorf("worker-%d: transient", workerID)}
						err := q.Retry(ctx, 0, errs, j.ID) // no delay so it's immediately available
						assert.NoError(t, err)
					case 2:
						// Permanent failure
						errs := map[string]error{j.ID: fmt.Errorf("worker-%d: permanent", workerID)}
						err := q.Fail(ctx, errs, j.ID)
						assert.NoError(t, err)
						failed.Add(1)
					}
				}
			}
		}(w)
	}
	wg.Wait()

	t.Logf("completed=%d, failed=%d", completed.Load(), failed.Load())

	// All jobs should have been either completed (moved to archive) or remain in the main table as failed
	archivedCount := countAllRows(t, db, "verification_tasks_archive")
	failedCount := countRows(t, db, "verification_tasks", jobqueue.JobStatusFailed)

	// Every job should be accounted for in one of these two places
	// Some jobs might still be pending if they were retried but workers exited before consuming them again.
	pendingCount := countRows(t, db, "verification_tasks", jobqueue.JobStatusPending)
	totalAccountedFor := archivedCount + failedCount + pendingCount
	assert.Equal(t, numJobs, totalAccountedFor, "all jobs should be accounted for")
}

func TestRetryExhaustionCycle(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.DefaultMaxAttempts = 3
	})
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: "exhaust", Data: "x"}))

	var jobID string

	// Attempt 1: consume → retry
	consumed, err := q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID = consumed[0].ID
	assert.Equal(t, 1, consumed[0].AttemptCount)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("err1")}, jobID))

	// Attempt 2: consume → retry
	consumed, err = q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	assert.Equal(t, 2, consumed[0].AttemptCount)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("err2")}, jobID))

	// Attempt 3: consume → retry (should now exceed max)
	consumed, err = q.Consume(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	assert.Equal(t, 3, consumed[0].AttemptCount)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("err3")}, jobID))

	// Job should now be in failed status (attempt_count=3 >= max_attempts=3)
	assert.Equal(t, 1, countRows(t, db, "verification_tasks", jobqueue.JobStatusFailed))

	// Verify last_error was recorded
	var lastErr string
	err = db.QueryRow("SELECT last_error FROM verification_tasks WHERE job_id = $1", jobID).Scan(&lastErr)
	require.NoError(t, err)
	assert.Equal(t, "err3", lastErr)
}

func TestCleanupMixed(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	// Create 3 jobs, complete all
	for i := 0; i < 3; i++ {
		require.NoError(t, q.Publish(ctx, testJob{Chain: "1", Message: fmt.Sprintf("cl-%d", i), Data: "x"}))
	}
	consumed, err := q.Consume(ctx, 3, time.Minute)
	require.NoError(t, err)
	require.Len(t, consumed, 3)

	ids := make([]string, 3)
	for i, j := range consumed {
		ids[i] = j.ID
	}
	require.NoError(t, q.Complete(ctx, ids...))
	assert.Equal(t, 3, countAllRows(t, db, "verification_tasks_archive"))

	// Back-date only 2 of them
	_, err = db.Exec(`
		UPDATE verification_tasks_archive
		SET completed_at = NOW() - INTERVAL '10 hours'
		WHERE job_id IN ($1, $2)`, ids[0], ids[1])
	require.NoError(t, err)

	// Cleanup with 1-hour retention: should delete only the 2 old ones
	deleted, err := q.Cleanup(ctx, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 2, deleted)
	assert.Equal(t, 1, countAllRows(t, db, "verification_tasks_archive"))
}

func TestConcurrentPublishStress(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	const (
		goroutines     = 10
		jobsPerRoutine = 10
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gID int) {
			defer wg.Done()
			for j := 0; j < jobsPerRoutine; j++ {
				time.Sleep(time.Duration(rand.Intn(2)) * time.Millisecond) //nolint:gosec
				err := q.Publish(ctx, testJob{
					Chain:   fmt.Sprintf("chain-%d", gID),
					Message: fmt.Sprintf("stress-%d-%d", gID, j),
					Data:    "payload",
				})
				assert.NoError(t, err)
			}
		}(g)
	}
	wg.Wait()

	total := countAllRows(t, db, "verification_tasks")
	assert.Equal(t, goroutines*jobsPerRoutine, total)
}

func TestEndToEndConcurrentWithRandomWork(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.DefaultMaxAttempts = 4
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const (
		numProducers    = 3
		jobsPerProducer = 15
		totalJobs       = numProducers * jobsPerProducer
		numConsumers    = 3
	)

	// --- Produce ---
	var wgPub sync.WaitGroup
	wgPub.Add(numProducers)
	for p := 0; p < numProducers; p++ {
		go func(pid int) {
			defer wgPub.Done()
			rng := rand.New(rand.NewSource(int64(pid))) //nolint:gosec
			for j := 0; j < jobsPerProducer; j++ {
				time.Sleep(time.Duration(rng.Intn(10)) * time.Millisecond)
				err := q.Publish(ctx, testJob{
					Chain:   fmt.Sprintf("e2e-chain-%d", pid),
					Message: fmt.Sprintf("e2e-%d-%d", pid, j),
					Data:    fmt.Sprintf("work-%d", j),
				})
				assert.NoError(t, err)
			}
		}(p)
	}
	wgPub.Wait()

	// --- Consume with random success/retry/fail ---
	var (
		completedCount atomic.Int64
		failedCount    atomic.Int64
		wgCon          sync.WaitGroup
	)
	wgCon.Add(numConsumers)
	for c := 0; c < numConsumers; c++ {
		go func(cid int) {
			defer wgCon.Done()
			rng := rand.New(rand.NewSource(int64(cid + 100))) //nolint:gosec
			emptyRounds := 0

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				batch, err := q.Consume(ctx, 4, time.Minute)
				if err != nil {
					return
				}
				if len(batch) == 0 {
					emptyRounds++
					if emptyRounds > 10 {
						return
					}
					time.Sleep(30 * time.Millisecond)
					continue
				}
				emptyRounds = 0

				for _, j := range batch {
					// Simulate random work duration
					time.Sleep(time.Duration(rng.Intn(8)) * time.Millisecond)

					roll := rng.Intn(100)
					switch {
					case roll < 60:
						// 60%: success
						_ = q.Complete(ctx, j.ID)
						completedCount.Add(1)
					case roll < 85:
						// 25%: retry (no delay, immediately available)
						_ = q.Retry(ctx, 0, map[string]error{j.ID: fmt.Errorf("transient-%d", cid)}, j.ID)
					default:
						// 15%: permanent fail
						_ = q.Fail(ctx, map[string]error{j.ID: fmt.Errorf("permanent-%d", cid)}, j.ID)
						failedCount.Add(1)
					}
				}
			}
		}(c)
	}
	wgCon.Wait()

	t.Logf("completed=%d, permanently_failed=%d", completedCount.Load(), failedCount.Load())

	archived := countAllRows(t, db, "verification_tasks_archive")
	remainingFailed := countRows(t, db, "verification_tasks", jobqueue.JobStatusFailed)
	remainingPending := countRows(t, db, "verification_tasks", jobqueue.JobStatusPending)

	totalAccounted := archived + remainingFailed + remainingPending
	assert.Equal(t, totalJobs, totalAccounted,
		"all %d jobs should be archived (%d) + failed (%d) + pending (%d)",
		totalJobs, archived, remainingFailed, remainingPending)
}
