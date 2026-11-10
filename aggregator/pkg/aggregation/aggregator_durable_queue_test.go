package aggregation

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestDurableQueue_SingleAggregatorProcessesEachRequest runs two aggregator replicas
// against one database and asserts every published request is processed exactly once.
func TestDurableQueue_SingleAggregatorProcessesEachRequest(t *testing.T) {
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	defer cleanup()
	require.NoError(t, postgres.RunMigrationsContext(t.Context(), ds, "postgres"))

	const requestCount = 60

	var mu sync.Mutex
	processed := make(map[string]int)

	newReplica := func(name string) (*CommitReportAggregator, *atomic.Int64) {
		var count atomic.Int64

		store := mocks.NewMockCommitVerificationStore(t)
		store.EXPECT().ListCommitVerificationByAggregationKey(mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, messageID model.MessageID, _ model.AggregationKey) ([]*model.CommitVerificationRecord, error) {
				mu.Lock()
				processed[string(messageID)]++
				mu.Unlock()
				count.Add(1)
				return nil, nil
			}).Maybe()

		quorum := mocks.NewMockQuorumValidator(t)
		quorum.EXPECT().CheckQuorum(mock.Anything, mock.Anything).Return(false, nil).Maybe()

		monitoring := mocks.NewMockAggregatorMonitoring(t)
		testutil.StubTracing(monitoring)
		metric := mocks.NewMockAggregatorMetricLabeler(t)
		metric.EXPECT().With(mock.Anything, mock.Anything).Return(metric).Maybe()
		metric.EXPECT().SetAggregationQueueSize(mock.Anything, mock.Anything).Maybe()
		monitoring.EXPECT().Metrics().Return(metric).Maybe()

		lggr := logger.Sugared(logger.Test(t))
		queue, err := NewQueue(ds, logger.With(lggr, "replica", name), metric.SetAggregationQueueSize)
		require.NoError(t, err)
		require.NoError(t, queue.Start(t.Context()))
		t.Cleanup(func() { require.NoError(t, queue.Close()) })

		config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 4}}
		return NewCommitReportAggregator(store, nil, mocks.NewMockSink(t), quorum, config, lggr, monitoring, queue), &count
	}

	replicaA, countA := newReplica("a")
	replicaB, countB := newReplica("b")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Every row is pending before either replica consumes, and both replicas have an
	// unconsumed signal, so they start racing for the same rows immediately.
	for i := range requestCount {
		publisher := replicaA
		if i%2 == 1 {
			publisher = replicaB
		}
		require.NoError(t, publisher.CheckAggregation(ctx, model.AggregationTrigger{MessageID: fmt.Appendf(nil, "message-%03d", i), AggregationKey: fmt.Sprintf("agg-key-%03d", i)}))
	}

	replicaA.StartBackground(ctx)
	replicaB.StartBackground(ctx)

	require.Eventually(t, func() bool {
		return countA.Load()+countB.Load() >= requestCount
	}, 60*time.Second, 50*time.Millisecond, "replicas did not drain the queue")

	// Let any duplicate delivery surface before asserting.
	time.Sleep(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, processed, requestCount, "every published message should have been processed")
	for messageID, times := range processed {
		assert.Equal(t, 1, times, "message %q was processed more than once", messageID)
	}
	assert.Positive(t, countA.Load(), "replica A did no work")
	assert.Positive(t, countB.Load(), "replica B did no work")
}

// TestDurableQueue_DedupPerAggregationKey asserts pending requests collapse per aggregation key,
// not per message: a message can carry several keys (one per CCV version).
func TestDurableQueue_DedupPerAggregationKey(t *testing.T) {
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	defer cleanup()
	require.NoError(t, postgres.RunMigrationsContext(t.Context(), ds, "postgres"))

	monitoring := mocks.NewMockAggregatorMonitoring(t)
	metric := mocks.NewMockAggregatorMetricLabeler(t)
	metric.EXPECT().SetAggregationQueueSize(mock.Anything, mock.Anything).Maybe()
	monitoring.EXPECT().Metrics().Return(metric).Maybe()

	lggr := logger.Sugared(logger.Test(t))
	queue, err := NewQueue(ds, lggr, metric.SetAggregationQueueSize)
	require.NoError(t, err)
	config := &model.AggregatorConfig{Aggregation: model.AggregationConfig{BackgroundWorkerCount: 1}}
	agg := NewCommitReportAggregator(mocks.NewMockCommitVerificationStore(t), nil, mocks.NewMockSink(t),
		mocks.NewMockQuorumValidator(t), config, lggr, monitoring, queue)

	ctx := t.Context()
	messageID := []byte("message-1")
	v1 := model.AggregationTrigger{MessageID: messageID, AggregationKey: "agg-key-v1"}
	v2 := model.AggregationTrigger{MessageID: messageID, AggregationKey: "agg-key-v2"}
	require.NoError(t, agg.CheckAggregation(ctx, v1))
	require.NoError(t, agg.CheckAggregation(ctx, v1, v2))

	size, err := queue.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, size, "one pending job per aggregation key")
}
