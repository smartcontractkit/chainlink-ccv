package worker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/indexer/testutil"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

// overlapStorage records when two replicas load the same message at the same time.
type overlapStorage struct {
	common.IndexerStorage
	mu       sync.Mutex
	inFlight map[protocol.Bytes32]int
	overlaps int
	loads    map[protocol.Bytes32]int
}

func newOverlapStorage(inner common.IndexerStorage) *overlapStorage {
	return &overlapStorage{IndexerStorage: inner, inFlight: map[protocol.Bytes32]int{}, loads: map[protocol.Bytes32]int{}}
}

func (s *overlapStorage) GetMessage(ctx context.Context, id protocol.Bytes32) (common.MessageWithMetadata, error) {
	s.mu.Lock()
	s.inFlight[id]++
	s.loads[id]++
	if s.inFlight[id] > 1 {
		s.overlaps++
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight[id]--
		s.mu.Unlock()
	}()
	time.Sleep(20 * time.Millisecond)
	return s.IndexerStorage.GetMessage(ctx, id)
}

func newDurableTestStorage(t *testing.T) (*storage.PostgresStorage, string) {
	t.Helper()
	uri, cleanup := testutil.SetupTestPostgresURI(t)
	t.Cleanup(cleanup)
	db, err := sqlx.Open("postgres", uri)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, storage.RunMigrationsContext(t.Context(), db))
	s, err := storage.NewPostgresStorage(t.Context(), logger.Test(t), monitoring.NewNoopIndexerMonitoring(), uri, pg.DriverPostgres, pg.DBConfig{MaxOpenConns: 20}, 0, 0)
	require.NoError(t, err)
	return s, uri
}

// persistMessages persists n messages with no CCVs, so each one succeeds at its first attempt.
func persistMessages(t *testing.T, s *storage.PostgresStorage, firstSeq, n int) []protocol.Bytes32 {
	t.Helper()
	msgs := make([]common.MessageWithMetadata, 0, n)
	ids := make([]protocol.Bytes32, 0, n)
	for i := range n {
		m := common.MessageWithMetadata{
			Message: protocol.Message{
				Version: 1, SourceChainSelector: 1, DestChainSelector: 2, Finality: 1,
				SequenceNumber: protocol.SequenceNumber(firstSeq + i),
			},
			Metadata: common.MessageMetadata{Status: common.MessageProcessing, IngestionTimestamp: time.Now().UTC()},
		}
		msgs = append(msgs, m)
		ids = append(ids, m.Message.MustMessageID())
	}
	require.NoError(t, s.PersistDiscoveryBatch(t.Context(), common.DiscoveryBatch{
		Messages: msgs, SequenceNumber: common.SequenceNumberNotSupported,
	}))
	return ids
}

func allSuccessful(t *testing.T, s common.IndexerStorage, ids []protocol.Bytes32) bool {
	for _, id := range ids {
		m, err := s.GetMessage(t.Context(), id)
		require.NoError(t, err)
		if m.Metadata.Status != common.MessageSuccessful {
			return false
		}
	}
	return true
}

func replicaPool(t *testing.T, s common.IndexerStorage, workers int) {
	t.Helper()
	p, err := NewWorkerPool(logger.Test(t), config.PoolConfig{ConcurrentWorkers: workers, WorkerTimeout: 5, PollInterval: 50}, testSchedulerCfg, registry.NewVerifierRegistry(), s)
	require.NoError(t, err)
	p.Start(t.Context())
	t.Cleanup(p.Stop)
}

func TestReplicas_ShareWorkWithoutOverlap(t *testing.T) {
	s, _ := newDurableTestStorage(t)
	ids := persistMessages(t, s, 1, 30)

	shared := newOverlapStorage(s)
	for range 3 {
		replicaPool(t, shared, 4)
	}

	require.Eventually(t, func() bool { return allSuccessful(t, s, ids) }, 20*time.Second, 100*time.Millisecond)
	shared.mu.Lock()
	defer shared.mu.Unlock()
	require.Zero(t, shared.overlaps, "two replicas worked on one message at the same time")
	for _, id := range ids {
		require.Equal(t, 1, shared.loads[id], "each message is processed once")
	}
}

// A replica that crashes holds its lease until it ends; then another replica claims the message.
func TestReplicas_ExpiredLeaseGoesToAnotherReplica(t *testing.T) {
	s, _ := newDurableTestStorage(t)
	ids := persistMessages(t, s, 100, 1)

	claimed, err := s.ClaimWork(t.Context(), 1, time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)

	replicaPool(t, s, 1)
	require.Never(t, func() bool { return allSuccessful(t, s, ids) }, 500*time.Millisecond, 50*time.Millisecond, "the lease still holds")
	require.Eventually(t, func() bool { return allSuccessful(t, s, ids) }, 10*time.Second, 100*time.Millisecond)
}
