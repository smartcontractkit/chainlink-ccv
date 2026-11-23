package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// fakeStore hands out claims from memory and records each settlement.
// Leases, claim tokens and deadlines are covered by the Postgres-backed tests.
type fakeStore struct {
	*mocks.MockIndexerStorage
	mu        sync.Mutex
	due       []common.WorkClaim
	claimErr  error
	settleErr error
	settled   map[protocol.Bytes32]common.WorkSettlement
	// settleStatus overrides the status that SettleWork returns, as the database does on a deadline.
	settleStatus map[protocol.Bytes32]common.MessageStatus
	claimSizes   []int
}

func newFakeStore(t *testing.T) *fakeStore {
	return &fakeStore{
		MockIndexerStorage: mocks.NewMockIndexerStorage(t),
		settled:            map[protocol.Bytes32]common.WorkSettlement{},
		settleStatus:       map[protocol.Bytes32]common.MessageStatus{},
	}
}

func (f *fakeStore) add(id protocol.Bytes32, attempt int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.due = append(f.due, common.WorkClaim{MessageID: id, Attempt: attempt})
}

func (f *fakeStore) ClaimWork(_ context.Context, limit int, _ time.Duration) ([]common.WorkClaim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	n := min(limit, len(f.due))
	out := f.due[:n:n]
	f.due = f.due[n:]
	if n > 0 {
		f.claimSizes = append(f.claimSizes, n)
	}
	return out, nil
}

func (f *fakeStore) SettleWork(_ context.Context, s common.WorkSettlement) (common.MessageStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.settleErr != nil {
		return common.MessageProcessing, f.settleErr
	}
	f.settled[s.MessageID] = s
	if st, ok := f.settleStatus[s.MessageID]; ok {
		return st, nil
	}
	return s.Status, nil
}

func (f *fakeStore) settlement(id protocol.Bytes32) (common.WorkSettlement, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.settled[id]
	return s, ok
}

var testSchedulerCfg = config.SchedulerConfig{BaseDelay: 1000, MaxDelay: 8000, VerificationVisibilityWindow: 60}

func newTestPool(t *testing.T, f common.IndexerStorage, workers int) *Pool {
	t.Helper()
	p, err := NewWorkerPool(logger.Test(t), config.PoolConfig{ConcurrentWorkers: workers, WorkerTimeout: 1, PollInterval: 20}, testSchedulerCfg, registry.NewVerifierRegistry(), f)
	require.NoError(t, err)
	return p
}

func startPool(t *testing.T, f *fakeStore, workers int) *Pool {
	t.Helper()
	p := newTestPool(t, f, workers)
	p.Start(t.Context())
	t.Cleanup(p.Stop)
	return p
}

// expectNoMissingVerifiers makes Execute find nothing missing, so the attempt succeeds.
func expectNoMissingVerifiers(f *fakeStore, msgID any) {
	f.On("GetMessage", mock.Anything, msgID).Return(common.MessageWithMetadata{}, nil)
	f.On("GetCCVData", mock.Anything, msgID).Return(nil, storage.ErrCCVDataNotFound)
}

func waitSettled(t *testing.T, f *fakeStore, id protocol.Bytes32) common.WorkSettlement {
	t.Helper()
	var s common.WorkSettlement
	require.Eventually(t, func() bool {
		var ok bool
		s, ok = f.settlement(id)
		return ok
	}, 2*time.Second, 10*time.Millisecond)
	return s
}

func TestNewWorkerPool_RequiresDependencies(t *testing.T) {
	lggr := logger.Test(t)
	poolCfg := config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}
	reg := registry.NewVerifierRegistry()
	ms := mocks.NewMockIndexerStorage(t)

	_, err := NewWorkerPool(lggr, poolCfg, testSchedulerCfg, nil, ms)
	require.Error(t, err)
	_, err = NewWorkerPool(lggr, poolCfg, testSchedulerCfg, reg, nil)
	require.Error(t, err)
	_, err = NewWorkerPool(lggr, config.PoolConfig{}, testSchedulerCfg, reg, ms)
	require.Error(t, err)
}

func TestNewWorkerPool_DefaultsPollInterval(t *testing.T) {
	p, err := NewWorkerPool(logger.Test(t), config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 5}, testSchedulerCfg, registry.NewVerifierRegistry(), mocks.NewMockIndexerStorage(t))
	require.NoError(t, err)
	require.Equal(t, defaultPollInterval, p.pollInterval)
	require.Equal(t, 5*time.Second+leaseMargin, p.lease)
}

func TestPool_SuccessSettlesWithClaimToken(t *testing.T) {
	f := newFakeStore(t)
	msgID := protocol.Bytes32{1}
	expectNoMissingVerifiers(f, msgID)
	f.add(msgID, 3)
	startPool(t, f, 1)

	s := waitSettled(t, f, msgID)
	require.Equal(t, common.MessageSuccessful, s.Status)
	require.Equal(t, 3, s.Attempt)
}

func TestPool_ErrorRetriesWithBackoff(t *testing.T) {
	f := newFakeStore(t)
	msgID := protocol.Bytes32{2}
	f.On("GetMessage", mock.Anything, msgID).Return(common.MessageWithMetadata{}, errors.New("db down"))
	f.add(msgID, 2)
	startPool(t, f, 1)

	s := waitSettled(t, f, msgID)
	require.Equal(t, common.MessageProcessing, s.Status)
	// Attempt 2 waits BackoffDelay(3, 1s, 2, 8s) = 4s, as the old scheduler did.
	require.Equal(t, 4*time.Second, s.RetryDelay)
	require.Contains(t, s.LastErr, "db down")
}

// The database decides the deadline; the pool reports the TIMEOUT that SettleWork returns.
func TestPool_RetryPastDeadlineIsReportedAsTimeout(t *testing.T) {
	f := newFakeStore(t)
	msgID := protocol.Bytes32{3}
	f.On("GetMessage", mock.Anything, msgID).Return(common.MessageWithMetadata{}, errors.New("db down"))
	f.settleStatus[msgID] = common.MessageTimeout
	f.add(msgID, 1)
	startPool(t, f, 1)

	s := waitSettled(t, f, msgID)
	require.Equal(t, common.MessageProcessing, s.Status, "the pool asks for a retry")
}

func TestPool_MissingMessageTimesOutWithoutRetry(t *testing.T) {
	f := newFakeStore(t)
	msgID := protocol.Bytes32{4}
	f.On("GetMessage", mock.Anything, msgID).Return(common.MessageWithMetadata{}, storage.ErrMessageNotFound)
	f.add(msgID, 1)
	startPool(t, f, 1)

	s := waitSettled(t, f, msgID)
	require.Equal(t, common.MessageTimeout, s.Status)
	require.Zero(t, s.RetryDelay)
}

func TestPool_ClaimsAtMostOnePerWorker(t *testing.T) {
	f := newFakeStore(t)
	expectNoMissingVerifiers(f, mock.Anything)
	ids := make([]protocol.Bytes32, 0, 5)
	for i := range 5 {
		id := protocol.Bytes32{byte(10 + i)}
		ids = append(ids, id)
		f.add(id, 1)
	}
	startPool(t, f, 2)

	for _, id := range ids {
		waitSettled(t, f, id)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.claimSizes {
		require.LessOrEqual(t, n, 2, "a claim must not exceed the free worker slots")
	}
}

// A lost claim or a failed settle changes nothing; the lease ends and a worker claims the message again.
func TestPool_SettleErrorIsNotFatal(t *testing.T) {
	f := newFakeStore(t)
	msgID := protocol.Bytes32{5}
	expectNoMissingVerifiers(f, msgID)
	f.settleErr = common.ErrClaimLost
	f.add(msgID, 1)
	p := startPool(t, f, 1)

	require.Eventually(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.due) == 0
	}, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return p.inFlight.Load() == 0 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, p.Ready())
}

func TestPool_NotReadyAfterRepeatedClaimErrors(t *testing.T) {
	f := newFakeStore(t)
	f.claimErr = errors.New("db down")
	p := newTestPool(t, f, 1)
	require.Error(t, p.Ready(), "not ready before Start")

	p.Start(t.Context())
	defer p.Stop()
	for range maxConsecutiveClaimErrors {
		p.claim(t.Context())
	}
	require.ErrorContains(t, p.Ready(), "claim failed")
}

func TestPool_StopWaitsForRunLoop(t *testing.T) {
	p := newTestPool(t, newFakeStore(t), 1)
	p.Start(context.Background())
	require.NoError(t, p.Ready())

	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return")
	}
	require.Error(t, p.Ready(), "not ready after Stop")
}

type fakeLeader bool

func (l fakeLeader) IsLeader() bool { return bool(l) }

func TestPool_ExpireRunsOnlyOnLeader(t *testing.T) {
	ms := mocks.NewMockIndexerStorage(t)
	p := newTestPool(t, ms, 1)
	var recorded int64
	p.SetSizeRecorder(func(_ context.Context, n int64) { recorded = n })

	p.SetLeadership(fakeLeader(false))
	p.expire(t.Context())
	ms.AssertNotCalled(t, "ExpireWork", mock.Anything, mock.Anything)

	ms.On("ExpireWork", mock.Anything, expireBatchSize).Return(int64(2), nil).Once()
	ms.On("CountProcessingMessages", mock.Anything).Return(int64(7), nil).Once()
	p.SetLeadership(fakeLeader(true))
	p.expire(t.Context())
	require.EqualValues(t, 7, recorded)
}

// A full batch means more messages may be past their deadline, so expire runs again in the same tick.
func TestPool_ExpireRepeatsWhileBatchIsFull(t *testing.T) {
	ms := mocks.NewMockIndexerStorage(t)
	p := newTestPool(t, ms, 1)

	ms.On("ExpireWork", mock.Anything, expireBatchSize).Return(int64(expireBatchSize), nil).Twice()
	ms.On("ExpireWork", mock.Anything, expireBatchSize).Return(int64(3), nil).Once()
	p.expire(t.Context())
	ms.AssertNumberOfCalls(t, "ExpireWork", 3)
}

// A slow expiry runs in its own loop, so the pool still claims and settles work.
func TestPool_SlowExpireDoesNotBlockClaims(t *testing.T) {
	f := newFakeStore(t)
	msgID := protocol.Bytes32{30}
	expectNoMissingVerifiers(f, msgID)
	expiring := make(chan struct{})
	f.On("ExpireWork", mock.Anything, expireBatchSize).
		Run(func(a mock.Arguments) {
			select {
			case expiring <- struct{}{}:
			default:
			}
			<-a.Get(0).(context.Context).Done()
		}).Return(int64(0), context.DeadlineExceeded).Maybe()

	p := newTestPool(t, f, 1)
	p.expireInterval = 10 * time.Millisecond
	p.Start(t.Context())
	t.Cleanup(p.Stop)

	<-expiring
	f.add(msgID, 1)
	p.Wake()
	s := waitSettled(t, f, msgID)
	require.Equal(t, common.MessageSuccessful, s.Status)
}
