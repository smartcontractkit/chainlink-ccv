package jobqueue_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// markProcessingSince backdates a job's started_at so the next stale sweep reclaims it.
func markProcessingSince(t *testing.T, ds sqlutil.DataSource, jobID string, age time.Duration) {
	t.Helper()
	query := fmt.Sprintf(
		"UPDATE %s SET status = 'processing', started_at = $1 WHERE job_id = $2",
		verifier.TaskVerifierJobsTableName,
	)
	_, err := ds.ExecContext(context.Background(), query, time.Now().Add(-age), jobID)
	require.NoError(t, err)
}

// Test_SplitConsumePaths covers ConsumePending and ReclaimStale, the two halves that the
// signal-driven consumer schedules independently. Consume keeps running both.
func Test_SplitConsumePaths(t *testing.T) {
	db := testutil.NewTestDB(t)

	newQueue := func(t *testing.T) *jobqueue.PostgresJobQueue[testJob] {
		t.Helper()
		q, err := jobqueue.NewPostgresJobQueue[testJob](db, jobqueue.QueueConfig{
			Name:          verifier.TaskVerifierJobsTableName,
			OwnerID:       t.Name(),
			RetryDuration: time.Hour,
			LockDuration:  time.Minute,
		}, logger.Test(t))
		require.NoError(t, err)
		return q
	}

	publish := func(t *testing.T, q *jobqueue.PostgresJobQueue[testJob], n int) {
		t.Helper()
		jobs := make([]testJob, n)
		for i := range jobs {
			jobs[i] = testJob{Chain: 1, Message: fmt.Appendf(nil, "msg-%d", i), Data: "d"}
		}
		require.NoError(t, q.Publish(context.Background(), jobs...))
	}

	t.Run("ConsumePending returns pending jobs and ignores stale ones", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		publish(t, q, 3)
		jobs, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 3)

		// Age one of them out. ConsumePending must not pick it back up: reclaiming stale
		// locks belongs to ReclaimStale, on its own timer.
		markProcessingSince(t, db, jobs[0].ID, 10*time.Minute)

		again, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		require.Empty(t, again, "ConsumePending must never reclaim a stale lock")
	})

	t.Run("ReclaimStale returns stale jobs and ignores pending ones", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		publish(t, q, 3)

		// Nothing is stale yet, and the pending backlog must not leak into this path.
		stale, err := q.ReclaimStale(ctx, 10)
		require.NoError(t, err)
		require.Empty(t, stale, "ReclaimStale must never return pending jobs")

		jobs, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 3)

		markProcessingSince(t, db, jobs[0].ID, 10*time.Minute)
		markProcessingSince(t, db, jobs[1].ID, 10*time.Minute)

		stale, err = q.ReclaimStale(ctx, 10)
		require.NoError(t, err)
		require.Len(t, stale, 2)
	})

	t.Run("each split path gets the full batch size", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		publish(t, q, 10)
		jobs, err := q.ConsumePending(ctx, 5)
		require.NoError(t, err)
		require.Len(t, jobs, 5, "ConsumePending must fill the whole batch")

		for _, j := range jobs {
			markProcessingSince(t, db, j.ID, 10*time.Minute)
		}

		// The stale budget is no longer shared with pending, so a stale sweep can fill a
		// batch of its own while a pending backlog is still waiting.
		stale, err := q.ReclaimStale(ctx, 5)
		require.NoError(t, err)
		require.Len(t, stale, 5)

		remaining, err := q.ConsumePending(ctx, 5)
		require.NoError(t, err)
		require.Len(t, remaining, 5, "the pending backlog is untouched by the stale sweep")
	})

	t.Run("Consume still runs both phases under one batch budget", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		publish(t, q, 6)
		jobs, err := q.ConsumePending(ctx, 2)
		require.NoError(t, err)
		require.Len(t, jobs, 2)

		markProcessingSince(t, db, jobs[0].ID, 10*time.Minute)
		markProcessingSince(t, db, jobs[1].ID, 10*time.Minute)

		// Two stale plus two pending, capped at the requested batch size. This is the
		// behavior every existing caller of Consume was written against.
		combined, err := q.Consume(ctx, 4)
		require.NoError(t, err)
		require.Len(t, combined, 4)
	})
}

// Test_ObservabilityDecoratorForwardsSignalCapability guards the wiring that the
// processors actually run against. They receive the decorator, never the queue, so a
// decorator that stopped forwarding would quietly push every verifier back to polling
// while every test that builds the queue directly kept passing.
func Test_ObservabilityDecoratorForwardsSignalCapability(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	queue, err := jobqueue.NewPostgresJobQueue[testJob](db, jobqueue.QueueConfig{
		Name:          verifier.TaskVerifierJobsTableName,
		OwnerID:       t.Name(),
		RetryDuration: time.Hour,
		LockDuration:  time.Minute,
	}, logger.Test(t))
	require.NoError(t, err)

	decorator, err := jobqueue.NewObservabilityDecorator(
		queue, logger.Test(t), time.Hour, func(context.Context, int64) {},
	)
	require.NoError(t, err)

	sdq, ok := jobqueue.JobQueue[testJob](decorator).(jobqueue.SignalDrivenQueue[testJob])
	require.True(t, ok, "the decorator must expose the signal capability")
	require.NotNil(t, sdq.Signals(), "a nil channel means the consumer falls back to polling")

	// The decorator must hand back the queue's own signal, not a channel of its own that
	// nothing ever writes to.
	require.NoError(t, queue.Publish(ctx, testJob{Chain: 1, Message: []byte("m"), Data: "d"}))
	select {
	case <-sdq.Signals():
	case <-time.After(5 * time.Second):
		t.Fatal("a publish on the wrapped queue did not reach the decorator's signal")
	}

	jobs, err := sdq.ConsumePending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, jobs, 1, "ConsumePending must reach the wrapped queue")

	stale, err := sdq.ReclaimStale(ctx, 10)
	require.NoError(t, err)
	require.Empty(t, stale, "ReclaimStale must reach the wrapped queue")
}
