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
)

// The two arms run at scaled intervals rather than production ones, so a scenario costs
// seconds instead of minutes. The ratio between them is what the assertions use, and it is
// preserved: 50ms against 3s is the same 1:60 as the 500ms against 30s that ships.
const (
	loadPollInterval  = 50 * time.Millisecond
	loadFallback      = 3 * time.Second
	loadIdleWindow    = 4 * time.Second
	loadIntervalRatio = float64(loadFallback) / float64(loadPollInterval) // 60
	// loadDrainTimeout is deliberately short and explicit. tests.WaitTimeout scales with
	// the -timeout flag, so a test that never reaches its condition would spin for many
	// minutes instead of failing.
	loadDrainTimeout = 30 * time.Second
)

// loadSeq hands out sequence numbers that are unique for the whole package run.
//
// A result's MessageID is derived from its sequence number, and the fake writer stores
// results in a map keyed by MessageID. Reusing a sequence number therefore makes two
// different publishes collapse into one stored entry, and any count that expects them to
// be distinct can never be reached.
var loadSeq atomic.Uint64

func uniqueResults(n int) []protocol.VerifierNodeResult {
	out := make([]protocol.VerifierNodeResult, n)
	for i := range out {
		out[i] = createTestVerifierNodeResult(loadSeq.Add(1))
	}
	return out
}

// waitForCount blocks until the fake writer holds want results, or fails.
func waitForCount(t *testing.T, storage *FakeCCVNodeDataWriter, want int, what string) time.Duration {
	t.Helper()

	began := time.Now()
	deadline := began.Add(loadDrainTimeout)
	for time.Now().Before(deadline) {
		if storage.GetStoredCount() >= want {
			return time.Since(began)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: only %d of %d results were written within %s", what, storage.GetStoredCount(), want, loadDrainTimeout)
	return 0
}

type armStarter func(t *testing.T, owner string, queue jobqueue.JobQueue[protocol.VerifierNodeResult], storage *FakeCCVNodeDataWriter, batchSize int) func()

// startPollingArm starts a processor on the legacy polling loop.
func startPollingArm(
	t *testing.T, owner string, queue jobqueue.JobQueue[protocol.VerifierNodeResult],
	storage *FakeCCVNodeDataWriter, batchSize int,
) func() {
	t.Helper()
	p, err := NewProcessorWithPollInterval(
		logger.Test(t), owner,
		verifiermonitoring.NewFakeVerifierMonitoring(), testutil.NoopLatencyTracker{},
		storage, queue,
		verifier.CoordinatorConfig{StorageBatchSize: batchSize, StorageRetryDelay: time.Second},
		loadPollInterval,
	)
	require.NoError(t, err)
	require.NoError(t, p.Start(t.Context()))
	return func() { require.NoError(t, p.Close()) }
}

// startSignalArm starts a processor on the signal-driven loop.
func startSignalArm(
	t *testing.T, owner string, queue jobqueue.JobQueue[protocol.VerifierNodeResult],
	storage *FakeCCVNodeDataWriter, batchSize int,
) func() {
	t.Helper()
	p, err := NewProcessor(
		logger.Test(t), owner,
		verifiermonitoring.NewFakeVerifierMonitoring(), testutil.NoopLatencyTracker{},
		storage, queue,
		verifier.CoordinatorConfig{StorageBatchSize: batchSize, StorageRetryDelay: time.Second},
		WithPendingFallbackInterval(loadFallback),
		WithStaleReclaimInterval(loadFallback),
	)
	require.NoError(t, err)
	require.NoError(t, p.Start(t.Context()))
	return func() { require.NoError(t, p.Close()) }
}

func newLoadRecorder(t *testing.T, db *sqlx.DB) *testutil.DBLoadRecorder {
	t.Helper()
	return testutil.NewDBLoadRecorder(t, db,
		verifier.StorageWriterJobsTableName,
		verifier.StorageWriterJobsTableName+"_archive",
	)
}

// Test_QueueLoad_AB measures how much work each consumption mode asks the database to do.
//
// The arms run one at a time against a shared container, each under its own owner_id, and
// every assertion is on a ratio rather than an absolute count, so the result holds on any
// machine.
func Test_QueueLoad_AB(t *testing.T) {
	db, statsAvailable := testutil.NewTestDBWithStats(t)
	if !statsAvailable {
		t.Skip("pg_stat_statements is unavailable, so database load cannot be measured")
	}
	rec := newLoadRecorder(t, db)

	t.Run("idle: the poll floor disappears", func(t *testing.T) {
		// This is the scenario the change exists for. With no traffic at all, polling
		// still queries twice per tick forever, and that fixed cost is what saturated the
		// shared database.
		measure := func(name string, start armStarter) testutil.DBLoadDelta {
			owner := fmt.Sprintf("load-idle-%s", name)
			queue := newResultQueue(t, db, owner)
			storage := NewFakeCCVNodeDataWriter()

			delta := rec.Measure(t, func() {
				stop := start(t, owner, queue, storage, 10)
				defer stop()
				time.Sleep(loadIdleWindow)
			})
			require.Zero(t, storage.GetStoredCount(), "no work existed, so nothing should have been written")
			return delta
		}

		polling := measure("polling", startPollingArm)
		signal := measure("signal", startSignalArm)

		polling.Log(t, "idle / polling")
		signal.Log(t, "idle / signal-driven")

		ratio := testutil.CallsRatio(polling, signal)
		t.Logf("IDLE  polling %.2f stmt/s   signal-driven %.2f stmt/s   reduction %.1fx",
			polling.CallsPerSecond, signal.CallsPerSecond, ratio)

		// The interval ratio is 60x. A third of that is asserted so the test is not
		// fragile on a loaded runner, while still failing loudly if the floor returns.
		require.GreaterOrEqual(t, ratio, loadIntervalRatio/3,
			"signal-driven consumption must remove most of the idle statement rate")

		// Scan shapes are deliberately not asserted here. These tables hold a handful of
		// rows, so a sequential scan is the correct plan and says nothing about
		// production behavior. TestExplainQueryPlans asserts the plan shapes against a
		// realistic dataset, which is where that check belongs.
	})

	t.Run("burst: no more statements per job, and no slower", func(t *testing.T) {
		// Under real work the raw statement rate is the wrong measure, because a consumer
		// that gets more done legitimately issues more statements. Cost per job is the
		// comparison that means something.
		const (
			total     = 100
			batchSize = 10
		)

		measure := func(name string, start armStarter) (testutil.DBLoadDelta, time.Duration) {
			owner := fmt.Sprintf("load-burst-%s", name)
			queue := newResultQueue(t, db, owner)
			storage := NewFakeCCVNodeDataWriter()
			require.NoError(t, queue.Publish(t.Context(), uniqueResults(total)...))

			var drained time.Duration
			delta := rec.Measure(t, func() {
				stop := start(t, owner, queue, storage, batchSize)
				defer stop()
				drained = waitForCount(t, storage, total, name+" burst")
			})
			return delta, drained
		}

		pollingLoad, pollingTime := measure("polling", startPollingArm)
		signalLoad, signalTime := measure("signal", startSignalArm)

		pollingLoad.Log(t, "burst / polling")
		signalLoad.Log(t, "burst / signal-driven")

		pollingPerJob := testutil.StatementsPerJob(pollingLoad, total)
		signalPerJob := testutil.StatementsPerJob(signalLoad, total)
		t.Logf("BURST %d jobs  polling %.2f stmt/job in %s   signal-driven %.2f stmt/job in %s",
			total, pollingPerJob, pollingTime, signalPerJob, signalTime)

		require.LessOrEqual(t, signalPerJob, pollingPerJob*1.2,
			"signal-driven consumption must not cost more statements per job")
		// Guards the re-arm rule: a coalesced signal stands for the whole burst, so a
		// consumer that stopped after one batch would need one fallback tick per batch.
		require.Less(t, signalTime, time.Duration(total/batchSize)*loadFallback,
			"the burst must drain from a coalesced signal, not one batch per fallback tick")
	})

	t.Run("steady traffic: same work, fewer statements", func(t *testing.T) {
		const (
			batches   = 5
			perBatch  = 4
			total     = batches * perBatch
			batchSize = 10
		)

		measure := func(name string, start armStarter) testutil.DBLoadDelta {
			owner := fmt.Sprintf("load-steady-%s", name)
			queue := newResultQueue(t, db, owner)
			storage := NewFakeCCVNodeDataWriter()

			return rec.Measure(t, func() {
				stop := start(t, owner, queue, storage, batchSize)
				defer stop()
				for range batches {
					require.NoError(t, queue.Publish(t.Context(), uniqueResults(perBatch)...))
					time.Sleep(150 * time.Millisecond)
				}
				waitForCount(t, storage, total, name+" steady")
			})
		}

		pollingLoad := measure("polling", startPollingArm)
		signalLoad := measure("signal", startSignalArm)

		pollingLoad.Log(t, "steady / polling")
		signalLoad.Log(t, "steady / signal-driven")

		pollingPerJob := testutil.StatementsPerJob(pollingLoad, total)
		signalPerJob := testutil.StatementsPerJob(signalLoad, total)
		t.Logf("STEADY %d jobs  polling %.2f stmt/job   signal-driven %.2f stmt/job",
			total, pollingPerJob, signalPerJob)

		require.Less(t, signalPerJob, pollingPerJob,
			"under light traffic, polling spends most of its statements finding nothing")
	})
}
