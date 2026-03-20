package jobqueue_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// testJob implements Jobable for testing purposes.
type testJob struct {
	Chain   uint64 `json:"chain"`
	Message []byte `json:"message"`
	Data    string `json:"data"`
}

func (j testJob) JobKey() (chainSelector uint64, messageID []byte) {
	return j.Chain, j.Message
}

// newTestQueue creates a PostgresJobQueue[testJob] backed by a real Postgres testcontainer.
// It uses the "ccv_task_verifier_jobs" table which is created by migrations.
func newTestQueue(t *testing.T, opts ...func(*jobqueue.QueueConfig)) (*jobqueue.PostgresJobQueue[testJob], sqlutil.DataSource) {
	t.Helper()

	db := testutil.NewTestDB(t)

	cfg := jobqueue.QueueConfig{
		Name:          verifier.TaskVerifierJobsTableName,
		OwnerID:       "test-verifier",
		RetryDuration: time.Hour,
		LockDuration:  time.Minute,
	}
	for _, o := range opts {
		o(&cfg)
	}

	q, err := jobqueue.NewPostgresJobQueue[testJob](db, cfg, logger.Test(t))
	require.NoError(t, err)
	return q, db
}

// countRows is a test helper that counts rows in a table with a given status filter.
func countRows(t *testing.T, ds sqlutil.DataSource, table string, status jobqueue.JobStatus) int {
	t.Helper()
	var count int
	err := ds.QueryRowxContext(context.Background(), fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE status = $1", table), string(status)).Scan(&count)
	require.NoError(t, err)
	return count
}

// countAllRows is a test helper that counts all rows in a table.
func countAllRows(t *testing.T, ds sqlutil.DataSource, table string) int {
	t.Helper()
	var count int
	err := ds.QueryRowxContext(context.Background(), fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
	require.NoError(t, err)
	return count
}

// countRowsWithOwner counts rows filtered by status and ownerID.
func countRowsWithOwner(t *testing.T, ds sqlutil.DataSource, table string, status jobqueue.JobStatus, ownerID string) int {
	t.Helper()
	var count int
	err := ds.QueryRowxContext(context.Background(),
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE status = $1 AND owner_id = $2", table),
		string(status), ownerID).Scan(&count)
	require.NoError(t, err)
	return count
}

// countAllRowsWithOwner counts all rows belonging to ownerID.
func countAllRowsWithOwner(t *testing.T, ds sqlutil.DataSource, table, ownerID string) int {
	t.Helper()
	var count int
	err := ds.QueryRowxContext(context.Background(),
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE owner_id = $1", table),
		ownerID).Scan(&count)
	require.NoError(t, err)
	return count
}

func Test_PostgresQueueOps(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Helper to create a queue with ownerID = t.Name() for each subtest
	newQueue := func(t *testing.T, opts ...func(*jobqueue.QueueConfig)) *jobqueue.PostgresJobQueue[testJob] {
		t.Helper()
		cfg := jobqueue.QueueConfig{
			Name:          verifier.TaskVerifierJobsTableName,
			OwnerID:       t.Name(),
			RetryDuration: time.Hour,
			LockDuration:  time.Minute,
		}
		for _, o := range opts {
			o(&cfg)
		}
		q, err := jobqueue.NewPostgresJobQueue[testJob](db, cfg, logger.Test(t))
		require.NoError(t, err)
		return q
	}

	t.Run("PublishAndConsume", func(t *testing.T) {
		q := newQueue(t)

		jobs := []testJob{
			{Chain: 1, Message: []byte("msg-1"), Data: "payload-1"},
			{Chain: 1, Message: []byte("msg-2"), Data: "payload-2"},
			{Chain: 2, Message: []byte("msg-3"), Data: "payload-3"},
		}

		// Publish
		require.NoError(t, q.Publish(ctx, jobs...))

		// Consume all
		consumed, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		require.Len(t, consumed, 3)

		// Verify payload round-trip
		payloads := map[string]testJob{}
		for _, j := range consumed {
			payloads[string(j.Payload.Message)] = j.Payload
			assert.Equal(t, j.Payload.Chain, j.ChainSelector)
			assert.Equal(t, j.Payload.Message, j.MessageID)
			assert.Equal(t, 1, j.AttemptCount)
			assert.WithinDuration(t, time.Now().Add(time.Hour), j.RetryDeadline, 5*time.Second)
			assert.NotNil(t, j.StartedAt)
		}
		assert.Equal(t, "payload-1", payloads["msg-1"].Data)
		assert.Equal(t, "payload-2", payloads["msg-2"].Data)
		assert.Equal(t, "payload-3", payloads["msg-3"].Data)
	})

	t.Run("PublishEmpty", func(t *testing.T) {
		q := newQueue(t)
		require.NoError(t, q.Publish(ctx))
	})

	t.Run("ConsumeEmpty", func(t *testing.T) {
		q := newQueue(t)
		consumed, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		assert.Empty(t, consumed)
	})

	t.Run("ConsumeRespectsAvailableAt", func(t *testing.T) {
		q := newQueue(t)

		// Publish with a 1-hour delay – should NOT be consumable now
		require.NoError(t, q.PublishWithDelay(ctx, time.Hour, testJob{Chain: 1, Message: []byte("delayed"), Data: "d"}))

		consumed, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		assert.Empty(t, consumed)
	})

	t.Run("ConsumeBatchSizeLimit", func(t *testing.T) {
		q := newQueue(t)

		for i := range 5 {
			require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: fmt.Appendf(nil, "m-%d", i), Data: "x"}))
		}

		consumed, err := q.Consume(ctx, 2)
		require.NoError(t, err)
		assert.Len(t, consumed, 2)
	})

	t.Run("ConsumeDoesNotReturnProcessingJobs", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		// First consume locks the job
		first, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		require.Len(t, first, 1)

		// Second consume should return nothing – job is processing
		second, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		assert.Empty(t, second)
	})

	t.Run("ConsumeReclaimsStaleLock", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		// Consume the job (LockDuration=1min won't expire naturally during the test).
		first, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, first, 1)
		jobID := first[0].ID
		assert.Equal(t, 1, first[0].AttemptCount)

		// Simulate a crashed worker by back-dating started_at to 10 minutes ago.
		_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs SET started_at = NOW() - INTERVAL '10 minutes' WHERE job_id = $1", jobID)
		require.NoError(t, err)

		// Create a second queue with a 15-minute lock on the same DB and ownerID.
		// Since the job's started_at is only 10min ago, 15min lock means it's still "fresh".
		qLong, err := jobqueue.NewPostgresJobQueue[testJob](db, jobqueue.QueueConfig{
			Name:          verifier.TaskVerifierJobsTableName,
			OwnerID:       t.Name(),
			RetryDuration: time.Hour,
			LockDuration:  15 * time.Minute,
		}, logger.Test(t))
		require.NoError(t, err)

		notReclaimed, err := qLong.Consume(ctx, 1)
		require.NoError(t, err)
		assert.Empty(t, notReclaimed, "job should not be reclaimed when lock has not expired")

		// Original queue with 1-minute lock SHOULD reclaim (started_at is 10 min ago, 10 > 1).
		reclaimed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, reclaimed, 1)
		assert.Equal(t, jobID, reclaimed[0].ID)
		assert.Equal(t, 2, reclaimed[0].AttemptCount, "attempt_count should be incremented on reclaim")
	})

	t.Run("ConsumeDoesNotReclaimFreshProcessingJob", func(t *testing.T) {
		q := newQueue(t, func(c *jobqueue.QueueConfig) {
			c.LockDuration = time.Hour
		})

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		// Consume with the configured long lock duration.
		first, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, first, 1)

		// A second consume should not reclaim because started_at is fresh.
		second, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		assert.Empty(t, second, "freshly consumed job should not be reclaimed while lock is still valid")
	})

	t.Run("ConsumeReclaimMultipleStaleJobs", func(t *testing.T) {
		q := newQueue(t, func(c *jobqueue.QueueConfig) {
			c.LockDuration = 10 * time.Minute
		})

		// Publish 5 jobs.
		for i := range 5 {
			require.NoError(t, q.Publish(ctx, testJob{
				Chain:   1,
				Message: fmt.Appendf(nil, "stale-%d", i),
				Data:    "x",
			}))
		}

		// Consume all 5 (simulating a worker that will crash).
		consumed, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		require.Len(t, consumed, 5)

		// Back-date started_at for only 3 of them to simulate partial crash (20min > 10min lock).
		for _, j := range consumed[:3] {
			_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs SET started_at = NOW() - INTERVAL '20 minutes' WHERE job_id = $1 AND owner_id = $2", j.ID, t.Name())
			require.NoError(t, err)
		}

		// Consume should reclaim exactly the 3 stale jobs.
		reclaimed, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		assert.Len(t, reclaimed, 3)

		reclaimedIDs := map[string]bool{}
		for _, j := range reclaimed {
			reclaimedIDs[j.ID] = true
			assert.Equal(t, 2, j.AttemptCount)
		}
		// Verify it's the right 3 jobs.
		for _, j := range consumed[:3] {
			assert.True(t, reclaimedIDs[j.ID], "expected job %s to be reclaimed", j.ID)
		}
		// The other 2 should not have been reclaimed.
		for _, j := range consumed[3:] {
			assert.False(t, reclaimedIDs[j.ID], "expected job %s to NOT be reclaimed", j.ID)
		}
	})

	t.Run("Complete", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)

		// Complete the job
		require.NoError(t, q.Complete(ctx, consumed[0].ID))

		// Main table should be empty, archive should have 1
		assert.Equal(t, 0, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs", t.Name()))
		assert.Equal(t, 1, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))
	})

	t.Run("CompleteEmpty", func(t *testing.T) {
		q := newQueue(t)
		require.NoError(t, q.Complete(ctx))
	})

	t.Run("CompleteNonExistentJob", func(t *testing.T) {
		q := newQueue(t)
		// Completing a non-existent job should not error, just affect 0 rows
		require.NoError(t, q.Complete(ctx, "00000000-0000-0000-0000-000000000000"))
		assert.Equal(t, 0, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))
	})

	t.Run("Retry", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)
		jobID := consumed[0].ID

		// Retry with an error message
		errs := map[string]error{jobID: errors.New("transient failure")}
		require.NoError(t, q.Retry(ctx, 0, errs, jobID))

		// Job should be back to pending (retry deadline not yet reached)
		assert.Equal(t, 1, countRowsWithOwner(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusPending, t.Name()))

		// Consume again (attempt 2)
		consumed2, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed2, 1)
		assert.Equal(t, 2, consumed2[0].AttemptCount)
	})

	t.Run("RetryExceedsDeadline", func(t *testing.T) {
		q := newQueue(t, func(c *jobqueue.QueueConfig) {
			c.RetryDuration = time.Millisecond // expires almost immediately
		})

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		// Small sleep to ensure retry_deadline has passed
		time.Sleep(5 * time.Millisecond)

		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)
		jobID := consumed[0].ID

		errs := map[string]error{jobID: errors.New("fatal")}
		require.NoError(t, q.Retry(ctx, 0, errs, jobID))

		// Job should be archived (not in active table) because retry deadline has passed
		assert.Equal(t, 0, countRowsWithOwner(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusFailed, t.Name()))
		assert.Equal(t, 0, countRowsWithOwner(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusPending, t.Name()))

		// Job should be in the archive
		assert.Equal(t, 1, countRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", jobqueue.JobStatusFailed, t.Name()))
	})

	t.Run("RetryWithDelay", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)

		// Retry with 1-hour delay
		errs := map[string]error{consumed[0].ID: errors.New("oops")}
		require.NoError(t, q.Retry(ctx, time.Hour, errs, consumed[0].ID))

		// Job is pending but available_at is in the future → not consumable
		second, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		assert.Empty(t, second)
	})

	t.Run("Fail", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)
		jobID := consumed[0].ID

		errs := map[string]error{jobID: errors.New("permanent")}
		require.NoError(t, q.Fail(ctx, errs, jobID))

		// Failed job should NOT be in the active table
		assert.Equal(t, 0, countRowsWithOwner(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusFailed, t.Name()))

		// Failed job should be in the archive
		assert.Equal(t, 1, countRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", jobqueue.JobStatusFailed, t.Name()))

		// Verify error is stored in the archive
		var lastErr string
		err = db.QueryRowxContext(ctx, "SELECT last_error FROM ccv_task_verifier_jobs_archive WHERE job_id = $1", jobID).Scan(&lastErr)
		require.NoError(t, err)
		assert.Equal(t, "permanent", lastErr)
	})

	t.Run("FailedJobsAreNotReconsumed", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)
		jobID := consumed[0].ID

		// Mark as failed
		require.NoError(t, q.Fail(ctx, map[string]error{jobID: errors.New("err")}, jobID))

		// Failed job should NOT be in the active table
		assert.Equal(t, 0, countRowsWithOwner(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusFailed, t.Name()))

		// Failed job should be in the archive
		assert.Equal(t, 1, countRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", jobqueue.JobStatusFailed, t.Name()))

		// Should NOT be consumable again
		consumed2, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		assert.Empty(t, consumed2, "failed jobs should not be consumed")
	})

	t.Run("Cleanup", func(t *testing.T) {
		q := newQueue(t)

		// Publish, consume, and complete a job so it lands in the archive
		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))
		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)
		require.NoError(t, q.Complete(ctx, consumed[0].ID))

		assert.Equal(t, 1, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))

		// Back-date the completed_at so cleanup will pick it up
		_, err = db.ExecContext(ctx,
			"UPDATE ccv_task_verifier_jobs_archive SET completed_at = NOW() - INTERVAL '2 hours' WHERE owner_id = $1",
			t.Name())
		require.NoError(t, err)

		deleted, err := q.Cleanup(ctx, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, 1, deleted)
		assert.Equal(t, 0, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))
	})

	t.Run("CleanupRetainsRecentJobs", func(t *testing.T) {
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))
		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.NoError(t, q.Complete(ctx, consumed[0].ID))

		// Cleanup with very long retention – nothing should be deleted
		deleted, err := q.Cleanup(ctx, 24*time.Hour)
		require.NoError(t, err)
		assert.Equal(t, 0, deleted)
		assert.Equal(t, 1, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))
	})

	t.Run("Size", func(t *testing.T) {
		q := newQueue(t)

		// Initially empty
		size, err := q.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, size)

		// Publish 5 jobs
		jobs := []testJob{
			{Chain: 1, Message: []byte("msg-1"), Data: "data1"},
			{Chain: 2, Message: []byte("msg-2"), Data: "data2"},
			{Chain: 3, Message: []byte("msg-3"), Data: "data3"},
			{Chain: 4, Message: []byte("msg-4"), Data: "data4"},
			{Chain: 5, Message: []byte("msg-5"), Data: "data5"},
		}
		require.NoError(t, q.Publish(ctx, jobs...))

		// Size should be 5 (all pending)
		size, err = q.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 5, size)

		// Consume 3 jobs (now processing)
		consumed, err := q.Consume(ctx, 3)
		require.NoError(t, err)
		require.Len(t, consumed, 3)

		// Size should still be 5 (2 pending + 3 processing)
		size, err = q.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 5, size)

		// Complete 2 jobs
		require.NoError(t, q.Complete(ctx, consumed[0].ID, consumed[1].ID))

		// Size should be 3 (2 pending + 1 processing)
		size, err = q.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 3, size)

		// Fail the last consumed job (it is archived immediately)
		require.NoError(t, q.Fail(ctx, map[string]error{consumed[2].ID: errors.New("test error")}, consumed[2].ID))

		// Size should be 2 (2 pending only - failed jobs are archived, not in active table)
		size, err = q.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, size)

		// Consume remaining jobs - should only get the 2 pending jobs
		// Failed jobs are archived and NOT consumed
		consumed2, err := q.Consume(ctx, 10)
		require.NoError(t, err)
		require.Len(t, consumed2, 2) // Only 2 pending jobs (failed job was archived)

		// Size should be 2 (2 processing)
		size, err = q.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, size)

		// Complete all remaining
		require.NoError(t, q.Complete(ctx, consumed2[0].ID, consumed2[1].ID))

		// Size should be 0
		size, err = q.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, size)
	})

	t.Run("FullLifecycle", func(t *testing.T) {
		q := newQueue(t)

		// 1. Publish
		require.NoError(t, q.Publish(ctx, testJob{Chain: 42, Message: []byte("lifecycle-1"), Data: "step1"}))

		// 2. Consume (attempt 1)
		consumed, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed, 1)
		jobID := consumed[0].ID
		assert.Equal(t, 1, consumed[0].AttemptCount)

		// 3. Retry (simulate transient failure)
		require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("timeout")}, jobID))

		// 4. Consume (attempt 2)
		consumed2, err := q.Consume(ctx, 1)
		require.NoError(t, err)
		require.Len(t, consumed2, 1)
		assert.Equal(t, jobID, consumed2[0].ID)
		assert.Equal(t, 2, consumed2[0].AttemptCount)

		// 5. Complete
		require.NoError(t, q.Complete(ctx, jobID))
		assert.Equal(t, 0, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs", t.Name()))
		assert.Equal(t, 1, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))

		// 6. Back-date and cleanup
		_, err = db.ExecContext(ctx,
			"UPDATE ccv_task_verifier_jobs_archive SET completed_at = NOW() - INTERVAL '48 hours' WHERE owner_id = $1",
			t.Name())
		require.NoError(t, err)
		deleted, err := q.Cleanup(ctx, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, 1, deleted)
	})

	t.Run("CleanupMixed", func(t *testing.T) {
		q := newQueue(t)

		// Create 3 jobs, complete all
		for i := range 3 {
			require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: fmt.Appendf(nil, "cl-%d", i), Data: "x"}))
		}
		consumed, err := q.Consume(ctx, 3)
		require.NoError(t, err)
		require.Len(t, consumed, 3)

		ids := make([]string, 3)
		for i, j := range consumed {
			ids[i] = j.ID
		}
		require.NoError(t, q.Complete(ctx, ids...))
		assert.Equal(t, 3, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))

		// Back-date only 2 of them
		_, err = db.ExecContext(ctx, `
			UPDATE ccv_task_verifier_jobs_archive
			SET completed_at = NOW() - INTERVAL '10 hours'
			WHERE job_id IN ($1, $2) AND owner_id = $3`, ids[0], ids[1], t.Name())
		require.NoError(t, err)

		// Cleanup with 1-hour retention: should delete only the 2 old ones
		deleted, err := q.Cleanup(ctx, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, 2, deleted)
		assert.Equal(t, 1, countAllRowsWithOwner(t, db, "ccv_task_verifier_jobs_archive", t.Name()))
	})
}

func TestConsumeReclaimConcurrentNoDuplicates(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.LockDuration = 10 * time.Minute
	})
	ctx := context.Background()

	const numJobs = 20

	for i := range numJobs {
		require.NoError(t, q.Publish(ctx, testJob{
			Chain:   1,
			Message: fmt.Appendf(nil, "concurrent-stale-%d", i),
			Data:    "x",
		}))
	}

	// Consume all, then back-date to make them stale.
	consumed, err := q.Consume(ctx, numJobs)
	require.NoError(t, err)
	require.Len(t, consumed, numJobs)

	_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs SET started_at = NOW() - INTERVAL '30 minutes'")
	require.NoError(t, err)

	// Launch multiple concurrent consumers to reclaim. Each should get a unique subset.
	var (
		seen sync.Map
		wg   sync.WaitGroup
	)
	numConsumers := 6
	wg.Add(numConsumers)
	for range numConsumers {
		go func() {
			defer wg.Done()
			for {
				batch, err := q.Consume(ctx, 5)
				if err != nil {
					return
				}
				if len(batch) == 0 {
					return
				}
				for _, j := range batch {
					if _, loaded := seen.LoadOrStore(j.ID, true); loaded {
						t.Errorf("duplicate stale job reclaimed: %s", j.ID)
					}
				}
				// Complete them so they don't get reclaimed again.
				ids := make([]string, len(batch))
				for i, j := range batch {
					ids[i] = j.ID
				}
				_ = q.Complete(ctx, ids...)
			}
		}()
	}
	wg.Wait()

	var count int
	seen.Range(func(_, _ any) bool { count++; return true })
	assert.Equal(t, numJobs, count, "all stale jobs should have been reclaimed exactly once")
}

func TestComplete(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)

	// Complete the job
	require.NoError(t, q.Complete(ctx, consumed[0].ID))

	// Main table should be empty, archive should have 1
	assert.Equal(t, 0, countAllRows(t, db, "ccv_task_verifier_jobs"))
	assert.Equal(t, 1, countAllRows(t, db, "ccv_task_verifier_jobs_archive"))
}

func TestCompleteEmpty(t *testing.T) {
	q, _ := newTestQueue(t)
	require.NoError(t, q.Complete(context.Background()))
}

func TestCompleteNonExistentJob(t *testing.T) {
	q, db := newTestQueue(t)
	// Completing a non-existent job should not error, just affect 0 rows
	require.NoError(t, q.Complete(context.Background(), "00000000-0000-0000-0000-000000000000"))
	assert.Equal(t, 0, countAllRows(t, db, "ccv_task_verifier_jobs_archive"))
}

func TestRetry(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID

	// Retry with an error message
	errs := map[string]error{jobID: errors.New("transient failure")}
	require.NoError(t, q.Retry(ctx, 0, errs, jobID))

	// Job should be back to pending (retry deadline not yet reached)
	assert.Equal(t, 1, countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusPending))

	// Consume again (attempt 2)
	consumed2, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed2, 1)
	assert.Equal(t, 2, consumed2[0].AttemptCount)
}

func TestRetryExceedsDeadline(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.RetryDuration = time.Millisecond // expires almost immediately
	})
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

	// Small sleep to ensure retry_deadline has passed
	time.Sleep(5 * time.Millisecond)

	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID

	errs := map[string]error{jobID: errors.New("fatal")}
	require.NoError(t, q.Retry(ctx, 0, errs, jobID))

	// Job exceeded retry deadline → immediately moved to archive as failed.
	assert.Equal(t, 0, countAllRows(t, db, "ccv_task_verifier_jobs"))
	assert.Equal(t, 1, countRows(t, db, "ccv_task_verifier_jobs_archive", jobqueue.JobStatusFailed))
}

func TestRetryWithDelay(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)

	// Retry with 1-hour delay
	errs := map[string]error{consumed[0].ID: errors.New("oops")}
	require.NoError(t, q.Retry(ctx, time.Hour, errs, consumed[0].ID))

	// Job is pending but available_at is in the future → not consumable
	second, err := q.Consume(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, second)
}

func TestFail(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID

	errs := map[string]error{jobID: errors.New("permanent")}
	require.NoError(t, q.Fail(ctx, errs, jobID))

	// Job is permanently failed → moved to archive immediately; main table must be empty.
	assert.Equal(t, 0, countAllRows(t, db, "ccv_task_verifier_jobs"))
	assert.Equal(t, 1, countRows(t, db, "ccv_task_verifier_jobs_archive", jobqueue.JobStatusFailed))

	// Verify error is stored in archive
	var lastErr string
	err = db.QueryRowxContext(ctx, "SELECT last_error FROM ccv_task_verifier_jobs_archive WHERE job_id = $1", jobID).Scan(&lastErr)
	require.NoError(t, err)
	assert.Equal(t, "permanent", lastErr)
}

// TestFailedJobsAreNotReconsumed verifies that permanently failed jobs are archived immediately
// and cannot be picked up again by Consume. We never want to retry what is permanently failed.
func TestFailedJobsAreNotReconsumed(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))

	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)

	// Mark as permanently failed
	require.NoError(t, q.Fail(ctx, map[string]error{consumed[0].ID: errors.New("err")}, consumed[0].ID))

	// Must NOT be consumable again — it is already in the archive.
	consumed2, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Empty(t, consumed2)
}

// TestConsumeMarksDeserializationFailuresAsFailed ensures that jobs with malformed JSON
// are marked as failed instead of being stuck in processing state forever.
func TestConsumeMarksDeserializationFailuresAsFailed(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	// Insert a job with incompatible JSON directly into the database
	// This simulates a scenario where the payload schema changed (breaking change)
	// Use an array instead of an object - valid JSON but incompatible with testJob struct
	malformedJobID := "00000000-0000-0000-0000-000000000001"
	_, err := db.ExecContext(ctx, `
		INSERT INTO ccv_task_verifier_jobs (
			job_id, task_data, status, available_at, created_at, attempt_count, 
			retry_deadline, chain_selector, message_id, owner_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		malformedJobID,
		[]byte(`["this", "is", "an", "array", "not", "an", "object"]`), // Valid JSON but incompatible type
		jobqueue.JobStatusPending,
		time.Now(),
		time.Now(),
		0,
		time.Now().Add(time.Hour),
		"1",
		[]byte("malformed-msg"),
		"test-verifier",
	)
	require.NoError(t, err)

	// Also insert a valid job to verify it's still consumed
	require.NoError(t, q.Publish(ctx, testJob{Chain: 2, Message: []byte("valid-msg"), Data: "valid"}))

	// Consume - should get only the valid job
	consumed, err := q.Consume(ctx, 10)
	require.NoError(t, err)
	require.Len(t, consumed, 1, "Should only consume the valid job")
	assert.Equal(t, "valid", consumed[0].Payload.Data)

	// Verify the malformed job was moved to archive as failed (not stuck in processing)
	assert.Equal(t, 0, countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusFailed))
	assert.Equal(t, 1, countRows(t, db, "ccv_task_verifier_jobs_archive", jobqueue.JobStatusFailed))

	// Verify error is stored in archive
	var lastError string
	err = db.QueryRowxContext(ctx, "SELECT last_error FROM ccv_task_verifier_jobs_archive WHERE job_id = $1", malformedJobID).Scan(&lastError)
	require.NoError(t, err)
	assert.Contains(t, lastError, "failed to unmarshal payload")
}

func TestCleanup(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	// Publish, consume, and complete a job so it lands in the archive
	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))
	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	require.NoError(t, q.Complete(ctx, consumed[0].ID))

	assert.Equal(t, 1, countAllRows(t, db, "ccv_task_verifier_jobs_archive"))

	// Back-date the completed_at so cleanup will pick it up
	_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs_archive SET completed_at = NOW() - INTERVAL '2 hours'")
	require.NoError(t, err)

	deleted, err := q.Cleanup(ctx, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
	assert.Equal(t, 0, countAllRows(t, db, "ccv_task_verifier_jobs_archive"))
}

func TestCleanupRetainsRecentJobs(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("m1"), Data: "x"}))
	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.NoError(t, q.Complete(ctx, consumed[0].ID))

	// Cleanup with very long retention – nothing should be deleted
	deleted, err := q.Cleanup(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
	assert.Equal(t, 1, countAllRows(t, db, "ccv_task_verifier_jobs_archive"))
}

func TestSize(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	// Initially empty
	size, err := q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, size)

	// Publish 5 jobs
	jobs := []testJob{
		{Chain: 1, Message: []byte("msg-1"), Data: "data1"},
		{Chain: 2, Message: []byte("msg-2"), Data: "data2"},
		{Chain: 3, Message: []byte("msg-3"), Data: "data3"},
		{Chain: 4, Message: []byte("msg-4"), Data: "data4"},
		{Chain: 5, Message: []byte("msg-5"), Data: "data5"},
	}
	require.NoError(t, q.Publish(ctx, jobs...))

	// Size should be 5 (all pending)
	size, err = q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, size)

	// Consume 3 jobs (now processing)
	consumed, err := q.Consume(ctx, 3)
	require.NoError(t, err)
	require.Len(t, consumed, 3)

	// Size should still be 5 (2 pending + 3 processing)
	size, err = q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, size)

	// Complete 2 jobs
	require.NoError(t, q.Complete(ctx, consumed[0].ID, consumed[1].ID))

	// Size should be 3 (2 pending + 1 processing)
	size, err = q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, size)

	// Fail the last consumed job — it is permanently failed and immediately archived.
	require.NoError(t, q.Fail(ctx, map[string]error{consumed[2].ID: errors.New("test error")}, consumed[2].ID))

	// Size should be 2 (2 pending; failed job was archived and is no longer in the active queue)
	size, err = q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, size)

	// Consume remaining jobs — only the 2 pending jobs; the failed job is gone.
	consumed2, err := q.Consume(ctx, 10)
	require.NoError(t, err)
	require.Len(t, consumed2, 2) // 2 pending only

	// Size should be 2 (both are now processing)
	size, err = q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, size)

	// Complete all remaining
	require.NoError(t, q.Complete(ctx, consumed2[0].ID, consumed2[1].ID))

	// Size should be 0
	size, err = q.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, size)
}

func TestFullLifecycle(t *testing.T) {
	q, db := newTestQueue(t)
	ctx := context.Background()

	// 1. Publish
	require.NoError(t, q.Publish(ctx, testJob{Chain: 42, Message: []byte("lifecycle-1"), Data: "step1"}))

	// 2. Consume (attempt 1)
	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID := consumed[0].ID
	assert.Equal(t, 1, consumed[0].AttemptCount)

	// 3. Retry (simulate transient failure)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("timeout")}, jobID))

	// 4. Consume (attempt 2)
	consumed2, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed2, 1)
	assert.Equal(t, jobID, consumed2[0].ID)
	assert.Equal(t, 2, consumed2[0].AttemptCount)

	// 5. Complete
	require.NoError(t, q.Complete(ctx, jobID))
	assert.Equal(t, 0, countAllRows(t, db, "ccv_task_verifier_jobs"))
	assert.Equal(t, 1, countAllRows(t, db, "ccv_task_verifier_jobs_archive"))

	// 6. Back-date and cleanup
	_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs_archive SET completed_at = NOW() - INTERVAL '48 hours'")
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
	for p := range numProducers {
		go func(producerID int) {
			defer wgPub.Done()
			for j := range jobsPerProducer {
				job := testJob{
					Chain:   uint64(producerID),
					Message: fmt.Appendf(nil, "msg-%d-%d", producerID, j),
					Data:    fmt.Sprintf("data-%d-%d", producerID, j),
				}
				// Random sleep to simulate realistic timing
				time.Sleep(time.Duration(rand.IntN(5)) * time.Millisecond)
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
	for range numConsumers {
		go func() {
			defer wgCon.Done()
			for {
				// Random sleep to simulate work
				time.Sleep(time.Duration(rand.IntN(3)) * time.Millisecond)
				batch, err := q.Consume(ctx, batchSize)
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
	assert.Equal(t, 0, countAllRows(t, db, "ccv_task_verifier_jobs"))
	assert.Equal(t, totalJobs, countAllRows(t, db, "ccv_task_verifier_jobs_archive"))
}

func TestConcurrentConsumersNoDuplicates(t *testing.T) {
	q, _ := newTestQueue(t)
	ctx := context.Background()

	const numJobs = 50
	for i := range numJobs {
		require.NoError(t, q.Publish(ctx, testJob{
			Chain:   1,
			Message: fmt.Appendf(nil, "dup-test-%d", i),
			Data:    "x",
		}))
	}

	var (
		seen sync.Map
		wg   sync.WaitGroup
	)
	numConsumers := 8
	wg.Add(numConsumers)
	for range numConsumers {
		go func() {
			defer wg.Done()
			for {
				batch, err := q.Consume(ctx, 3)
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
		c.RetryDuration = time.Hour
	})
	ctx := context.Background()

	const numJobs = 30

	for i := range numJobs {
		require.NoError(t, q.Publish(ctx, testJob{
			Chain:   1,
			Message: fmt.Appendf(nil, "rf-%d", i),
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
	for w := range numWorkers {
		go func(workerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(workerID), uint64(workerID+1)))

			for {
				batch, err := q.Consume(ctx, 5)
				if err != nil {
					return
				}
				if len(batch) == 0 {
					// Give retried jobs time to become available
					time.Sleep(20 * time.Millisecond)
					batch, err = q.Consume(ctx, 5)
					if err != nil || len(batch) == 0 {
						return
					}
				}

				for _, j := range batch {
					// Simulate random work
					time.Sleep(time.Duration(rng.IntN(5)) * time.Millisecond)

					outcome := rng.IntN(3) // 0=complete, 1=retry, 2=fail
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

	// All jobs should be archived (either completed or failed)
	// Some jobs might still be pending if they were retried but workers exited before consuming them again
	archivedCount := countAllRows(t, db, "ccv_task_verifier_jobs_archive")
	pendingCount := countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusPending)

	// Failed jobs should be in archive, not in active table
	failedInActiveTable := countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusFailed)
	assert.Equal(t, 0, failedInActiveTable, "failed jobs should be archived, not in active table")

	totalAccountedFor := archivedCount + pendingCount
	assert.Equal(t, numJobs, totalAccountedFor, "all jobs should be either archived or pending")
}

func TestRetryDeadlineExhaustionCycle(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.RetryDuration = 50 * time.Millisecond
	})
	ctx := context.Background()

	require.NoError(t, q.Publish(ctx, testJob{Chain: 1, Message: []byte("exhaust"), Data: "x"}))

	var jobID string

	// Attempt 1: consume → retry (deadline not yet reached)
	consumed, err := q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	jobID = consumed[0].ID
	assert.Equal(t, 1, consumed[0].AttemptCount)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("err1")}, jobID))

	// Attempt 2: consume → retry (deadline not yet reached)
	consumed, err = q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	assert.Equal(t, 2, consumed[0].AttemptCount)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("err2")}, jobID))

	// Wait for the retry deadline to expire
	time.Sleep(60 * time.Millisecond)

	// Attempt 3: consume → retry (deadline has now passed, should fail permanently and archive)
	consumed, err = q.Consume(ctx, 1)
	require.NoError(t, err)
	require.Len(t, consumed, 1)
	assert.Equal(t, 3, consumed[0].AttemptCount)
	require.NoError(t, q.Retry(ctx, 0, map[string]error{jobID: errors.New("err3")}, jobID))

	// Job should now be archived (not in active table) because retry deadline passed
	assert.Equal(t, 0, countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusFailed))
	assert.Equal(t, 0, countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusPending))

	// Job should be in the archive with failed status
	assert.Equal(t, 1, countRows(t, db, "ccv_task_verifier_jobs_archive", jobqueue.JobStatusFailed))

	// Verify last_error was recorded in the archive
	var lastErr string
	err = db.QueryRowxContext(ctx, "SELECT last_error FROM ccv_task_verifier_jobs_archive WHERE job_id = $1", jobID).Scan(&lastErr)
	require.NoError(t, err)
	assert.Equal(t, "err3", lastErr)
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
	for g := range goroutines {
		go func(gID int) {
			defer wg.Done()
			for j := range jobsPerRoutine {
				time.Sleep(time.Duration(rand.IntN(2)) * time.Millisecond)
				err := q.Publish(ctx, testJob{
					Chain:   uint64(gID),
					Message: fmt.Appendf(nil, "stress-%d-%d", gID, j),
					Data:    "payload",
				})
				assert.NoError(t, err)
			}
		}(g)
	}
	wg.Wait()

	total := countAllRows(t, db, "ccv_task_verifier_jobs")
	assert.Equal(t, goroutines*jobsPerRoutine, total)
}

func TestEndToEndConcurrentWithRandomWork(t *testing.T) {
	q, db := newTestQueue(t, func(c *jobqueue.QueueConfig) {
		c.RetryDuration = time.Hour
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
	for p := range numProducers {
		go func(pid int) {
			defer wgPub.Done()
			rng := rand.New(rand.NewPCG(uint64(pid), uint64(pid+1)))
			for j := range jobsPerProducer {
				time.Sleep(time.Duration(rng.IntN(10)) * time.Millisecond)
				err := q.Publish(ctx, testJob{
					Chain:   uint64(pid),
					Message: fmt.Appendf(nil, "e2e-%d-%d", pid, j),
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
	for c := range numConsumers {
		go func(cid int) {
			defer wgCon.Done()
			rng := rand.New(rand.NewPCG(uint64(cid+100), uint64(cid+101)))
			emptyRounds := 0

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				batch, err := q.Consume(ctx, 4)
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
					time.Sleep(time.Duration(rng.IntN(8)) * time.Millisecond)

					roll := rng.IntN(100)
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

	archived := countAllRows(t, db, "ccv_task_verifier_jobs_archive")
	remainingFailed := countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusFailed)
	remainingPending := countRows(t, db, "ccv_task_verifier_jobs", jobqueue.JobStatusPending)

	// Failed jobs should be archived, not in active table
	assert.Equal(t, 0, remainingFailed, "failed jobs should be archived, not in active table")

	totalAccounted := archived + remainingPending
	assert.Equal(t, totalJobs, totalAccounted,
		"all %d jobs should be archived (%d) + pending (%d)",
		totalJobs, archived, remainingPending)
}
