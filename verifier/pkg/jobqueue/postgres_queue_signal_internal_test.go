package jobqueue

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// signalJob is a minimal Jobable for the signal tests.
type signalJob struct {
	Chain   uint64 `json:"chain"`
	Message []byte `json:"message"`
}

func (j signalJob) JobKey() (chainSelector uint64, messageID []byte) {
	return j.Chain, j.Message
}

func signalJobs(n int) []signalJob {
	jobs := make([]signalJob, n)
	for i := range jobs {
		jobs[i] = signalJob{Chain: 1, Message: fmt.Appendf(nil, "msg-%d", i)}
	}
	return jobs
}

// countPendingOnFreshConn counts pending rows over a connection checked out separately
// from any transaction the queue is running. An uncommitted row is invisible to it.
func countPendingOnFreshConn(tb testing.TB, db *sqlx.DB, owner string) int {
	tb.Helper()

	ctx := context.Background()
	conn, err := db.Connx(ctx)
	require.NoError(tb, err)
	defer func() { _ = conn.Close() }()

	var count int
	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM %s WHERE owner_id = $1 AND status = 'pending'",
		verifier.TaskVerifierJobsTableName,
	)
	require.NoError(tb, conn.GetContext(ctx, &count, query, owner))
	return count
}

func Test_PostgresQueueSignalling(t *testing.T) {
	db := testutil.NewTestDB(t)

	// Each subtest owns its rows through owner_id, so one container serves all of them.
	newQueue := func(t *testing.T) *PostgresJobQueue[signalJob] {
		t.Helper()
		q, err := NewPostgresJobQueue[signalJob](db, QueueConfig{
			Name:          verifier.TaskVerifierJobsTableName,
			OwnerID:       t.Name(),
			RetryDuration: time.Hour,
			LockDuration:  time.Minute,
		}, logger.Test(t))
		require.NoError(t, err)
		return q
	}

	t.Run("Publish signals only after the transaction commits", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		// The signal wakes a consumer that queries on a different pooled connection. If it
		// were sent from inside the transaction, that consumer would read pre-commit state,
		// find nothing, and never be woken for these rows again.
		var pendingAtSignal int
		var signaled bool
		q.testOnlyOnSignal = func() {
			signaled = true
			pendingAtSignal = countPendingOnFreshConn(t, db, q.ownerID)
		}

		require.NoError(t, q.Publish(ctx, signalJobs(3)...))

		require.True(t, signaled, "Publish must signal")
		require.Equal(t, 3, pendingAtSignal,
			"the rows must already be committed and visible to another connection when the signal fires")
	})

	t.Run("Publish wakes a waiting consumer", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		require.False(t, drained(q.signal), "no work has been published yet")
		require.NoError(t, q.Publish(ctx, signalJobs(1)...))
		require.True(t, drained(q.signal))
	})

	t.Run("Publishing nothing does not wake a consumer", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx))
		require.False(t, drained(q.signal), "an empty publish creates no work")
	})

	t.Run("Complete and Fail do not wake a consumer", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, signalJobs(2)...))
		jobs, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 2)

		<-q.signal.C() // clear the publish token

		require.NoError(t, q.Complete(ctx, jobs[0].ID))
		require.NoError(t, q.Fail(ctx, map[string]error{}, jobs[1].ID))

		// Neither can move a row back to pending, so a signal would only wake the consumer
		// to find nothing.
		require.False(t, drained(q.signal))
	})

	t.Run("Retry signals once the delay has passed, not before", func(t *testing.T) {
		ctx := context.Background()
		q := newQueue(t)

		require.NoError(t, q.Publish(ctx, signalJobs(1)...))
		jobs, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 1)

		<-q.signal.C() // clear the publish token

		const delay = 300 * time.Millisecond
		require.NoError(t, q.Retry(ctx, delay, map[string]error{}, jobs[0].ID))

		// The row is pending again but not due yet, so waking now would cost a query that
		// matches nothing.
		require.False(t, drained(q.signal), "the retry signal must not fire before the delay")

		select {
		case <-q.signal.C():
		case <-time.After(5 * time.Second):
			t.Fatal("the retry never signaled, so it would have waited for the fallback poll")
		}
	})

	t.Run("Retry past the deadline archives and does not signal", func(t *testing.T) {
		ctx := context.Background()
		q, err := NewPostgresJobQueue[signalJob](db, QueueConfig{
			Name:          verifier.TaskVerifierJobsTableName,
			OwnerID:       t.Name(),
			RetryDuration: -time.Hour, // already expired at publish time
			LockDuration:  time.Minute,
		}, logger.Test(t))
		require.NoError(t, err)

		require.NoError(t, q.Publish(ctx, signalJobs(1)...))
		jobs, err := q.ConsumePending(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 1)

		<-q.signal.C() // clear the publish token

		require.NoError(t, q.Retry(ctx, 0, map[string]error{}, jobs[0].ID))

		// The job was archived rather than made pending, so there is nothing to wake for.
		require.False(t, drained(q.signal))
	})
}
