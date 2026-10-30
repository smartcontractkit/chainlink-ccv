package aggregator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/testutil"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// blockingStatsStore uses the real Postgres lock, but OrphanedKeyStats blocks until unblock
// is closed and ignores ctx. This simulates a scan that is stuck.
type blockingStatsStore struct {
	common.CommitVerificationStore
	entered chan struct{}
	unblock chan struct{}
}

func (s *blockingStatsStore) OrphanedKeyStats(context.Context, time.Time) (*model.OrphanStats, error) {
	close(s.entered)
	<-s.unblock
	return &model.OrphanStats{}, nil
}

func newPostgresStore(t *testing.T) *postgres.DatabaseStorage {
	t.Helper()
	ds, cleanup := testutil.SetupTestPostgresDB(t)
	t.Cleanup(cleanup)
	require.NoError(t, postgres.RunMigrationsContext(t.Context(), ds, "postgres"))
	return postgres.NewDatabaseStorage(ds, 10, 10*time.Second, logger.Sugared(logger.Test(t)))
}

func permissiveMetrics(t *testing.T) *mocks.MockAggregatorMetricLabeler {
	metrics := mocks.NewMockAggregatorMetricLabeler(t)
	metrics.EXPECT().With("component", "orphan_recoverer").Return(metrics).Maybe()
	metrics.EXPECT().SetOrphanBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().SetOrphanExpiredBacklog(mock.Anything, mock.Anything).Maybe()
	metrics.EXPECT().IncrementOrphanRecoveryErrors(mock.Anything).Maybe()
	return metrics
}

func TestOrphanRecoverer_Lock_ReleasedWhenScanTimeoutExpiresAndScanIsStuck(t *testing.T) {
	db := newPostgresStore(t)
	stuck := &blockingStatsStore{CommitVerificationStore: db, entered: make(chan struct{}), unblock: make(chan struct{})}
	defer close(stuck.unblock)

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:           true,
			Interval:          5 * time.Minute,
			MaxAge:            24 * time.Hour,
			ScanTimeout:       500 * time.Millisecond,
			LockReleaseMargin: time.Minute, // long, so only the process-side release can free the lock in time
			PageSize:          100,
		},
	}
	recoverer := NewOrphanRecoverer(stuck, mocks.NewMockAggregationTriggerer(t), config, logger.Sugared(logger.Test(t)), permissiveMetrics(t))

	go func() { _, _ = recoverer.RecoverOrphans(context.Background()) }()
	<-stuck.entered

	_, acquired, err := db.TryAcquireOrphanRecoveryLock(context.Background(), time.Minute)
	require.NoError(t, err)
	require.False(t, acquired, "lock must be held while the scan runs")

	require.Eventually(t, func() bool {
		release, ok, err := db.TryAcquireOrphanRecoveryLock(context.Background(), time.Minute)
		if err != nil || !ok {
			return false
		}
		release()
		return true
	}, 2*time.Second, 50*time.Millisecond, "lock must be released when the scan timeout expires")
}

func TestOrphanRecoverer_Lock_OnlyOneReplicaScansAtATime(t *testing.T) {
	db := newPostgresStore(t)
	first := &blockingStatsStore{CommitVerificationStore: db, entered: make(chan struct{}), unblock: make(chan struct{})}

	config := &model.AggregatorConfig{
		OrphanRecovery: model.OrphanRecoveryConfig{
			Enabled:           true,
			Interval:          5 * time.Minute,
			MaxAge:            24 * time.Hour,
			ScanTimeout:       time.Minute,
			LockReleaseMargin: time.Second,
			PageSize:          100,
		},
	}

	replicaA := NewOrphanRecoverer(first, mocks.NewMockAggregationTriggerer(t), config, logger.Sugared(logger.Test(t)), permissiveMetrics(t))

	var skipped atomic.Int32
	metricsB := permissiveMetrics(t)
	metricsB.EXPECT().IncrementOrphanRecoverySkipped(mock.Anything).Run(func(context.Context) { skipped.Add(1) })
	// Replica B uses the real store with no override, so the scanned flag shows if B scanned.
	replicaB := NewOrphanRecoverer(db, mocks.NewMockAggregationTriggerer(t), config, logger.Sugared(logger.Test(t)), metricsB)

	doneA := make(chan error, 1)
	go func() {
		_, err := replicaA.RecoverOrphans(context.Background())
		doneA <- err
	}()
	<-first.entered

	scanned, err := replicaB.RecoverOrphans(context.Background())
	require.NoError(t, err)
	require.False(t, scanned, "replica B must skip while replica A holds the lock")
	require.Equal(t, int32(1), skipped.Load())

	close(first.unblock)
	require.NoError(t, <-doneA)

	scanned, err = replicaB.RecoverOrphans(context.Background())
	require.NoError(t, err)
	require.True(t, scanned, "replica B must scan after replica A releases the lock")
}
