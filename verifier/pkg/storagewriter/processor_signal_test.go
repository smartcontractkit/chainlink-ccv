package storagewriter

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	verifiermonitoring "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// neverSignals wraps a queue and reports a channel that nothing ever writes to.
//
// This is how a lost signal is simulated: the consumer still runs its normal loop, but the
// signal arm never fires, so only the fallback poll can reach the work.
type neverSignals struct {
	jobqueue.JobQueue[protocol.VerifierNodeResult]
	dead chan struct{}
}

func newNeverSignals(q jobqueue.JobQueue[protocol.VerifierNodeResult]) *neverSignals {
	return &neverSignals{JobQueue: q, dead: make(chan struct{})}
}

func (n *neverSignals) Signals() <-chan struct{} { return n.dead }

func newResultQueue(t *testing.T, db *sqlx.DB, owner string) *jobqueue.PostgresJobQueue[protocol.VerifierNodeResult] {
	t.Helper()
	q, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](db, jobqueue.QueueConfig{
		Name:          verifier.StorageWriterJobsTableName,
		OwnerID:       owner,
		RetryDuration: time.Hour,
		LockDuration:  time.Minute,
	}, logger.Test(t))
	require.NoError(t, err)
	return q
}

func startProcessor(
	t *testing.T,
	queue jobqueue.JobQueue[protocol.VerifierNodeResult],
	storage *FakeCCVNodeDataWriter,
	batchSize int,
	opts ...Option,
) {
	t.Helper()
	p, err := NewProcessor(
		logger.Test(t),
		"test-"+t.Name(),
		verifiermonitoring.NewFakeVerifierMonitoring(),
		testutil.NoopLatencyTracker{},
		storage,
		queue,
		verifier.CoordinatorConfig{StorageBatchSize: batchSize, StorageRetryDelay: 100 * time.Millisecond},
		opts...,
	)
	require.NoError(t, err)
	require.NoError(t, p.Start(t.Context()))
	t.Cleanup(func() { require.NoError(t, p.Close()) })
}

// resultSeq hands out sequence numbers that stay unique for the whole package run.
//
// A result's MessageID is derived from its sequence number, and the fake writer stores
// results in a map keyed by MessageID. Reusing a sequence number would make two publishes
// collapse into one stored entry, so a count expecting them to be distinct could never be
// reached.
var resultSeq atomic.Uint64

// results returns n distinct results.
func results(n int) []protocol.VerifierNodeResult {
	out := make([]protocol.VerifierNodeResult, n)
	for i := range out {
		out[i] = createTestVerifierNodeResult(resultSeq.Add(1))
	}
	return out
}

// Test_SignalDrivenLiveness covers the paths where a signal is absent or unreliable. The
// rule under test is that a missing signal costs latency and never costs a job.
func Test_SignalDrivenLiveness(t *testing.T) {
	db := testutil.NewTestDB(t)

	t.Run("a lost signal is covered by the fallback poll", func(t *testing.T) {
		ctx := t.Context()
		owner := "test-" + t.Name()
		queue := newResultQueue(t, db, owner)
		storage := NewFakeCCVNodeDataWriter()

		startProcessor(t, newNeverSignals(queue), storage, 10,
			WithPendingFallbackInterval(300*time.Millisecond),
			WithStaleReclaimInterval(time.Hour),
		)

		require.NoError(t, queue.Publish(ctx, results(3)...))

		require.Eventually(t, func() bool {
			return storage.GetStoredCount() == 3
		}, tests.WaitTimeout(t), 50*time.Millisecond,
			"the fallback poll must still pick the jobs up when no signal arrives")
	})

	t.Run("work published by another process is picked up", func(t *testing.T) {
		ctx := t.Context()
		owner := "test-" + t.Name()
		storage := NewFakeCCVNodeDataWriter()

		// The processor's own queue handle never sees this publish, so no in-process
		// signal fires. This is the shape of the out-of-process job queue CLI, and of a
		// restart where ON CONFLICT DO NOTHING drops the re-published rows.
		consumerQueue := newResultQueue(t, db, owner)
		producerQueue := newResultQueue(t, db, owner)

		startProcessor(t, consumerQueue, storage, 10,
			WithPendingFallbackInterval(300*time.Millisecond),
			WithStaleReclaimInterval(time.Hour),
		)

		require.NoError(t, producerQueue.Publish(ctx, results(3)...))

		require.Eventually(t, func() bool {
			return storage.GetStoredCount() == 3
		}, tests.WaitTimeout(t), 50*time.Millisecond,
			"a row made pending by another process must still be consumed")
	})

	t.Run("work waiting before startup is picked up without any signal", func(t *testing.T) {
		ctx := t.Context()
		owner := "test-" + t.Name()
		storage := NewFakeCCVNodeDataWriter()

		// Published before the processor exists, so nothing could have signaled it.
		// The consumer must look once on start rather than wait for the first fallback.
		seedQueue := newResultQueue(t, db, owner)
		require.NoError(t, seedQueue.Publish(ctx, results(5)...))

		startProcessor(t, newResultQueue(t, db, owner), storage, 10,
			WithPendingFallbackInterval(time.Hour), // the fallback must not be what saves us
			WithStaleReclaimInterval(time.Hour),
		)

		require.Eventually(t, func() bool {
			return storage.GetStoredCount() == 5
		}, tests.WaitTimeout(t), 50*time.Millisecond,
			"a backlog present at startup must be consumed without waiting for the fallback")
	})

	t.Run("stale locks are reclaimed on their own timer", func(t *testing.T) {
		ctx := t.Context()
		owner := "test-" + t.Name()
		storage := NewFakeCCVNodeDataWriter()

		queue := newResultQueue(t, db, owner)
		require.NoError(t, queue.Publish(ctx, results(4)...))

		// Lock the jobs and abandon them, as a crashed worker would.
		jobs, err := queue.ConsumePending(ctx, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 4)
		for _, j := range jobs {
			query := fmt.Sprintf(
				"UPDATE %s SET started_at = $1 WHERE job_id = $2",
				verifier.StorageWriterJobsTableName,
			)
			_, err := db.ExecContext(ctx, query, time.Now().Add(-time.Hour), j.ID)
			require.NoError(t, err)
		}

		// No publish happens after startup, so no signal can fire, and the pending poll is
		// disabled. Only the stale sweep can recover these.
		startProcessor(t, newResultQueue(t, db, owner), storage, 10,
			WithPendingFallbackInterval(time.Hour),
			WithStaleReclaimInterval(200*time.Millisecond),
		)

		require.Eventually(t, func() bool {
			return storage.GetStoredCount() == 4
		}, tests.WaitTimeout(t), 50*time.Millisecond,
			"stale locks must be reclaimed by the stale timer alone")
	})
}

// Test_SignalDrivenBurstDrain guards the re-arm rule.
//
// Signals coalesce, so a burst of any size arrives as a single token. Without a re-arm
// after a non-empty batch the consumer would process one batch and then wait for the
// fallback, which looks correct at low load and stalls badly under burst.
func Test_SignalDrivenBurstDrain(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := t.Context()

	const (
		total     = 200
		batchSize = 10
	)

	owner := "test-" + t.Name()
	queue := newResultQueue(t, db, owner)
	storage := NewFakeCCVNodeDataWriter()

	// Both timers are effectively disabled, so the whole burst must drain from the single
	// signal that the publish produces.
	startProcessor(t, queue, storage, batchSize,
		WithPendingFallbackInterval(time.Hour),
		WithStaleReclaimInterval(time.Hour),
	)

	require.NoError(t, queue.Publish(ctx, results(total)...))

	require.Eventually(t, func() bool {
		return storage.GetStoredCount() == total
	}, tests.WaitTimeout(t), 50*time.Millisecond,
		"the burst must drain on one signal; %d batches were needed", total/batchSize)
}
