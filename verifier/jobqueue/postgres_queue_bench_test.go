package jobqueue_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// BenchmarkJobQueueThroughput measures end-to-end throughput of the PostgreSQL job queue
// under heavy concurrent load: 10 producers publishing batches of 100 jobs and
// 10 consumers processing 20 jobs at a time.
//
// Run with:
//
//	go test -bench=BenchmarkJobQueueThroughput -benchtime=1x -timeout=300s ./verifier/jobqueue/
func BenchmarkJobQueueThroughput(b *testing.B) {
	const (
		numProducers   = 10
		numConsumers   = 10
		batchesPerProd = 10  // number of Publish calls per producer
		jobsPerBatch   = 100 // jobs per Publish call
		batchConsume   = 20  // jobs per Consume call
		retryPct       = 10  // percent of consumed jobs retried (transient)
		failPct        = 5   // percent of consumed jobs permanently failed
		lockDuration   = 5 * time.Minute
	)

	sqlxDB := testutil.NewTestDB(b)

	q, err := jobqueue.NewPostgresJobQueue[testJob](sqlxDB.(*sqlx.DB).DB, jobqueue.QueueConfig{
		Name:          "verification_tasks",
		OwnerID:       "bench-verifier",
		RetryDuration: time.Hour,
	}, logger.Test(b))
	require.NoError(b, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db := sqlxDB.(*sqlx.DB)

	for b.Loop() {
		// Clean tables between iterations so each iteration starts fresh.
		_, err := db.ExecContext(ctx, "TRUNCATE verification_tasks, verification_tasks_archive CASCADE")
		require.NoError(b, err)

		var (
			publishedTotal atomic.Int64
			consumedTotal  atomic.Int64
			completedTotal atomic.Int64
			retriedTotal   atomic.Int64
			failedTotal    atomic.Int64
		)

		totalExpected := int64(numProducers * batchesPerProd * jobsPerBatch)

		// Phase 1: Producers
		start := time.Now()

		var wgProd sync.WaitGroup
		wgProd.Add(numProducers)
		for p := range numProducers {
			go func(pid int) {
				defer wgProd.Done()
				for batchIdx := range batchesPerProd {
					batch := make([]testJob, 0, jobsPerBatch)
					for j := range jobsPerBatch {
						batch = append(batch, testJob{
							Chain:   fmt.Sprintf("bench-chain-%d", pid),
							Message: fmt.Sprintf("bench-%d-%d-%d", pid, batchIdx, j),
							Data:    fmt.Sprintf("payload-%d-%d-%d", pid, batchIdx, j),
						})
					}
					if err := q.Publish(ctx, batch...); err != nil {
						require.NoError(b, err, "producer %d batch %d: publish error", pid, batchIdx)
						return
					}
					publishedTotal.Add(int64(len(batch)))
				}
			}(p)
		}
		wgProd.Wait()
		publishDuration := time.Since(start)

		// Phase 2: Consumers
		var wgCons sync.WaitGroup
		wgCons.Add(numConsumers)
		for c := range numConsumers {
			go func(cid int) {
				defer wgCons.Done()
				rng := rand.New(rand.NewPCG(uint64(cid), uint64(cid+1)))
				emptyStreak := 0

				for {
					select {
					case <-ctx.Done():
						return
					default:
					}

					batch, err := q.Consume(ctx, batchConsume, lockDuration)
					if err != nil {
						require.NoError(b, err, "consumer %d: consume error", cid)
						return
					}

					if len(batch) == 0 {
						emptyStreak++
						if emptyStreak > 30 {
							return
						}
						time.Sleep(15 * time.Millisecond)
						continue
					}
					emptyStreak = 0
					consumedTotal.Add(int64(len(batch)))

					var toComplete []string
					retryErrs := make(map[string]error)
					var retryIDs []string
					failErrs := make(map[string]error)
					var failIDs []string

					for _, j := range batch {
						roll := rng.IntN(100)
						switch {
						case roll < retryPct:
							retryErrs[j.ID] = fmt.Errorf("transient-%d", cid)
							retryIDs = append(retryIDs, j.ID)
						case roll < retryPct+failPct:
							failErrs[j.ID] = fmt.Errorf("permanent-%d", cid)
							failIDs = append(failIDs, j.ID)
						default:
							toComplete = append(toComplete, j.ID)
						}
					}

					if len(toComplete) > 0 {
						err := q.Complete(ctx, toComplete...)
						require.NoError(b, err, "consumer %d: complete error", cid)
						completedTotal.Add(int64(len(toComplete)))
					}
					if len(retryIDs) > 0 {
						err := q.Retry(ctx, 0, retryErrs, retryIDs...)
						require.NoError(b, err, "consumer %d: retry error", cid)
						retriedTotal.Add(int64(len(retryIDs)))
					}
					if len(failIDs) > 0 {
						err := q.Fail(ctx, failErrs, failIDs...)
						require.NoError(b, err, "consumer %d: fail error", cid)
						failedTotal.Add(int64(len(failIDs)))
					}
				}
			}(c)
		}
		wgCons.Wait()
		totalDuration := time.Since(start)

		published := publishedTotal.Load()
		consumed := consumedTotal.Load()
		completed := completedTotal.Load()
		retried := retriedTotal.Load()
		failed := failedTotal.Load()

		b.ReportMetric(float64(published)/publishDuration.Seconds(), "publish-jobs/sec")
		b.ReportMetric(float64(consumed)/totalDuration.Seconds(), "consume-jobs/sec")
		b.ReportMetric(float64(completed)/totalDuration.Seconds(), "complete-jobs/sec")
		b.ReportMetric(float64(totalDuration.Milliseconds()), "total-ms")

		b.Logf("Duration: %s", totalDuration)
		b.Logf("  Publish phase:  %s (%.0f jobs/sec)", publishDuration, float64(published)/publishDuration.Seconds())
		b.Logf("  Published:      %d", published)
		b.Logf("  Consumed:       %d (includes retried jobs re-consumed)", consumed)
		b.Logf("  Completed:      %d", completed)
		b.Logf("  Retried:        %d", retried)
		b.Logf("  Perm. failed:   %d", failed)

		var remaining int
		err = db.QueryRow("SELECT COUNT(*) FROM verification_tasks").Scan(&remaining)
		require.NoError(b, err, "count remaining")

		var archived int
		err = db.QueryRow("SELECT COUNT(*) FROM verification_tasks_archive").Scan(&archived)
		require.NoError(b, err, "count archived")
		b.Logf("  Remaining in queue: %d, Archived: %d, Sum: %d (expected %d)",
			remaining, archived, remaining+archived, totalExpected)

		require.Equal(b, totalExpected, int64(remaining+archived),
			"job leak: published=%d but remaining=%d + archived=%d = %d",
			totalExpected, remaining, archived, remaining+archived)
	}
}
