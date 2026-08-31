package taskverifier_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/taskverifier"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// signalTestTimeout is short and explicit. It must not scale with the -timeout flag, or a
// test that never reaches its condition would spin for minutes instead of failing.
const signalTestTimeout = 30 * time.Second

func signalTasks(n int, seqOffset uint64) []verifier.VerificationTask {
	tasks := make([]verifier.VerificationTask, n)
	for i := range tasks {
		msg := protocol.Message{
			SequenceNumber:      protocol.SequenceNumber(seqOffset + uint64(i)),
			SourceChainSelector: 1337,
		}
		tasks[i] = verifier.VerificationTask{MessageID: msg.MustMessageID().String(), Message: msg}
	}
	return tasks
}

func newSignalQueues(t *testing.T, db *sqlx.DB, owner string) (
	task *jobqueue.PostgresJobQueue[verifier.VerificationTask],
	result *jobqueue.PostgresJobQueue[protocol.VerifierNodeResult],
) {
	t.Helper()
	lggr := logger.Nop()

	task, err := jobqueue.NewPostgresJobQueue[verifier.VerificationTask](db, jobqueue.QueueConfig{
		Name:          verifier.TaskVerifierJobsTableName,
		OwnerID:       owner,
		RetryDuration: time.Hour,
		LockDuration:  time.Minute,
	}, lggr)
	require.NoError(t, err)

	result, err = jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](db, jobqueue.QueueConfig{
		Name:          verifier.StorageWriterJobsTableName,
		OwnerID:       owner,
		RetryDuration: time.Hour,
		LockDuration:  time.Minute,
	}, lggr)
	require.NoError(t, err)

	return task, result
}

func waitForProcessed(t *testing.T, v *fakeVerifierDB, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(signalTestTimeout)
	for time.Now().Before(deadline) {
		if v.GetProcessedCount() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: only %d of %d tasks were verified within %s", what, v.GetProcessedCount(), want, signalTestTimeout)
}

// Test_TaskVerifierSignalDriven mirrors the storage writer's coverage. The two run loops
// are deliberately identical, and divergence between them is the failure mode that no
// existing test would notice.
func Test_TaskVerifierSignalDriven(t *testing.T) {
	db := testutil.NewTestDB(t)

	start := func(t *testing.T, owner string, task jobqueue.JobQueue[verifier.VerificationTask],
		result jobqueue.JobQueue[protocol.VerifierNodeResult], v *fakeVerifierDB, batch int, opts ...taskverifier.Option,
	) {
		t.Helper()
		p, err := taskverifier.NewProcessor(
			logger.Nop(), owner, v, monitoring.NewFakeVerifierMonitoring(),
			testutil.NoopLatencyTracker{}, task, result, batch, opts...,
		)
		require.NoError(t, err)
		require.NoError(t, p.Start(t.Context()))
		t.Cleanup(func() { require.NoError(t, p.Close()) })
	}

	t.Run("a publish wakes the verifier", func(t *testing.T) {
		ctx := t.Context()
		owner := "sig-" + t.Name()
		taskQ, resultQ := newSignalQueues(t, db, owner)
		v := &fakeVerifierDB{}

		// Both timers are effectively off, so only the signal can drive this.
		start(t, owner, taskQ, resultQ, v, 10,
			taskverifier.WithPendingFallbackInterval(time.Hour),
			taskverifier.WithStaleReclaimInterval(time.Hour),
		)

		require.NoError(t, taskQ.Publish(ctx, signalTasks(3, 1000)...))
		waitForProcessed(t, v, 3, "publish wake")
	})

	t.Run("a burst drains from one coalesced signal", func(t *testing.T) {
		ctx := t.Context()
		owner := "sig-" + t.Name()
		taskQ, resultQ := newSignalQueues(t, db, owner)
		v := &fakeVerifierDB{}

		const (
			total = 120
			batch = 10
		)

		start(t, owner, taskQ, resultQ, v, batch,
			taskverifier.WithPendingFallbackInterval(time.Hour),
			taskverifier.WithStaleReclaimInterval(time.Hour),
		)

		// One publish yields one token, so only the re-arm rule can produce the remaining
		// batches. Without it this stops at the first batch.
		require.NoError(t, taskQ.Publish(ctx, signalTasks(total, 2000)...))
		waitForProcessed(t, v, total, "burst drain")
	})

	t.Run("verified results reach the result queue", func(t *testing.T) {
		ctx := t.Context()
		owner := "sig-" + t.Name()
		taskQ, resultQ := newSignalQueues(t, db, owner)
		v := &fakeVerifierDB{}

		start(t, owner, taskQ, resultQ, v, 10,
			taskverifier.WithPendingFallbackInterval(time.Hour),
			taskverifier.WithStaleReclaimInterval(time.Hour),
		)

		require.NoError(t, taskQ.Publish(ctx, signalTasks(4, 3000)...))
		waitForProcessed(t, v, 4, "result hop")

		// This is the hop the pipeline's end-to-end latency depends on: the task verifier
		// publishes to the result queue, which must in turn wake the storage writer.
		deadline := time.Now().Add(signalTestTimeout)
		for time.Now().Before(deadline) {
			var count int
			query := fmt.Sprintf(
				"SELECT COUNT(*) FROM %s WHERE owner_id = $1", verifier.StorageWriterJobsTableName,
			)
			require.NoError(t, db.GetContext(ctx, &count, query, owner))
			if count == 4 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("verified results never reached the result queue")
	})

	t.Run("work waiting before startup is picked up", func(t *testing.T) {
		ctx := t.Context()
		owner := "sig-" + t.Name()
		seedTaskQ, _ := newSignalQueues(t, db, owner)

		// Published before the processor exists, so nothing could have signaled it.
		require.NoError(t, seedTaskQ.Publish(ctx, signalTasks(5, 4000)...))

		taskQ, resultQ := newSignalQueues(t, db, owner)
		v := &fakeVerifierDB{}
		start(t, owner, taskQ, resultQ, v, 10,
			taskverifier.WithPendingFallbackInterval(time.Hour), // the fallback must not be what saves us
			taskverifier.WithStaleReclaimInterval(time.Hour),
		)

		waitForProcessed(t, v, 5, "startup backlog")
	})
}
