package chainstatus

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const testFlushInterval = 20 * time.Millisecond

// writeRecorder collects the batches that the batcher writes to the manager.
type writeRecorder struct {
	mu      sync.Mutex
	batches [][]protocol.ChainStatusInfo
}

func (r *writeRecorder) record(statuses []protocol.ChainStatusInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	batch := make([]protocol.ChainStatusInfo, len(statuses))
	copy(batch, statuses)
	r.batches = append(r.batches, batch)
}

func (r *writeRecorder) all() [][]protocol.ChainStatusInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]protocol.ChainStatusInfo, len(r.batches))
	copy(out, r.batches)
	return out
}

func (r *writeRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

func newTestBatcher(t *testing.T) (*Batcher, *mocks.MockChainStatusManager) {
	t.Helper()
	mockManager := mocks.NewMockChainStatusManager(t)
	batcher, err := NewChainStatusBatcher(logger.Test(t), mockManager, testFlushInterval)
	require.NoError(t, err)
	return batcher, mockManager
}

func status(selector protocol.ChainSelector, height int64, disabled bool) protocol.ChainStatusInfo {
	return protocol.ChainStatusInfo{
		ChainSelector:        selector,
		FinalizedBlockHeight: big.NewInt(height),
		Disabled:             disabled,
	}
}

func TestChainStatusBatcher_NewValidation(t *testing.T) {
	mockManager := mocks.NewMockChainStatusManager(t)

	_, err := NewChainStatusBatcher(nil, mockManager, testFlushInterval)
	require.Error(t, err)

	_, err = NewChainStatusBatcher(logger.Test(t), nil, testFlushInterval)
	require.Error(t, err)

	_, err = NewChainStatusBatcher(logger.Test(t), mockManager, 0)
	require.Error(t, err)
}

func TestChainStatusBatcher_EnabledStatusIsBuffered(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	// No write must reach the manager before the flush interval passes.
	require.NoError(t, batcher.WriteChainStatuses(t.Context(), []protocol.ChainStatusInfo{
		status(1, 100, false),
	}))
	mockManager.AssertNotCalled(t, "WriteChainStatuses", mock.Anything, mock.Anything)
}

func TestChainStatusBatcher_TickerFlushesBuffer(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			recorder.record(statuses)
			return nil
		})

	require.NoError(t, batcher.Start(t.Context()))
	t.Cleanup(func() { _ = batcher.Close() })

	require.NoError(t, batcher.WriteChainStatuses(t.Context(), []protocol.ChainStatusInfo{
		status(1, 100, false),
	}))

	require.Eventually(t, func() bool { return recorder.count() >= 1 }, time.Second, 5*time.Millisecond)

	batches := recorder.all()
	require.Len(t, batches[0], 1)
	require.Equal(t, protocol.ChainSelector(1), batches[0][0].ChainSelector)
	require.Equal(t, big.NewInt(100), batches[0][0].FinalizedBlockHeight)
}

func TestChainStatusBatcher_LastWriteWinsPerChain(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			recorder.record(statuses)
			return nil
		})

	ctx := t.Context()
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 100, false)}))
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 200, false)}))
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 300, false)}))

	require.NoError(t, batcher.flush(ctx))

	batches := recorder.all()
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 1)
	require.Equal(t, big.NewInt(300), batches[0][0].FinalizedBlockHeight)
}

func TestChainStatusBatcher_DisabledStatusFlushesImmediately(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			recorder.record(statuses)
			return nil
		})

	ctx := t.Context()
	// Chain 1 is buffered and must not reach the manager yet.
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 100, false)}))
	require.Equal(t, 0, recorder.count())

	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(2, 0, true)}))

	// The disable is written on its own first, so a bad row for another chain cannot
	// stop it. The buffered remainder follows in a second write.
	batches := recorder.all()
	require.Len(t, batches, 2)

	require.Len(t, batches[0], 1)
	require.Equal(t, protocol.ChainSelector(2), batches[0][0].ChainSelector)
	require.True(t, batches[0][0].Disabled)

	require.Len(t, batches[1], 1)
	require.Equal(t, protocol.ChainSelector(1), batches[1][0].ChainSelector)
	require.False(t, batches[1][0].Disabled)
}

func TestChainStatusBatcher_ReadIsPassthrough(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	selectors := []protocol.ChainSelector{1, 2}
	stored := status(1, 100, false)
	expected := map[protocol.ChainSelector]*protocol.ChainStatusInfo{1: &stored}
	mockManager.EXPECT().ReadChainStatuses(mock.Anything, selectors).Return(expected, nil)

	ctx := t.Context()
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 500, false)}))

	result, err := batcher.ReadChainStatuses(ctx, selectors)
	require.NoError(t, err)
	require.Equal(t, expected, result)
}

func TestChainStatusBatcher_ReadReturnsManagerError(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	expectedErr := errors.New("read failed")
	mockManager.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).Return(nil, expectedErr)

	_, err := batcher.ReadChainStatuses(t.Context(), []protocol.ChainSelector{1})
	require.ErrorIs(t, err, expectedErr)
}

func TestChainStatusBatcher_CloseFlushesRemainder(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			recorder.record(statuses)
			return nil
		}).Maybe()

	// A long interval makes sure the ticker does not flush before Close.
	batcher.flushInterval = time.Hour

	require.NoError(t, batcher.Start(t.Context()))
	require.NoError(t, batcher.WriteChainStatuses(t.Context(), []protocol.ChainStatusInfo{status(1, 100, false)}))
	require.NoError(t, batcher.Close())

	batches := recorder.all()
	require.Len(t, batches, 1)
	require.Equal(t, protocol.ChainSelector(1), batches[0][0].ChainSelector)
}

func TestChainStatusBatcher_FlushFailureRetries(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	var attempts int
	recorder := &writeRecorder{}
	var mu sync.Mutex
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			mu.Lock()
			attempts++
			first := attempts == 1
			mu.Unlock()
			if first {
				return errors.New("write failed")
			}
			recorder.record(statuses)
			return nil
		})

	ctx := t.Context()
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 100, false)}))

	// The first flush fails and the status stays in the buffer.
	require.Error(t, batcher.flush(ctx))

	require.NoError(t, batcher.Start(ctx))
	t.Cleanup(func() { _ = batcher.Close() })

	require.Eventually(t, func() bool { return recorder.count() >= 1 }, time.Second, 5*time.Millisecond)
	batches := recorder.all()
	require.Equal(t, big.NewInt(100), batches[0][0].FinalizedBlockHeight)
}

func TestChainStatusBatcher_FlushFailureKeepsNewerValue(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		Return(errors.New("write failed")).Once()

	ctx := t.Context()
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 100, false)}))

	// Drain the buffer manually, then write a newer value before the restore.
	batcher.mu.Lock()
	drained := batcher.pending
	batcher.pending = make(map[protocol.ChainSelector]protocol.ChainStatusInfo)
	batcher.mu.Unlock()

	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 200, false)}))
	batcher.restore(drained)

	batcher.mu.Lock()
	kept := batcher.pending[1]
	batcher.mu.Unlock()
	require.Equal(t, big.NewInt(200), kept.FinalizedBlockHeight)

	// Keep the Once expectation satisfied.
	require.Error(t, batcher.flush(ctx))
}

func TestChainStatusBatcher_EmptyWriteIsNoop(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	require.NoError(t, batcher.WriteChainStatuses(t.Context(), nil))
	mockManager.AssertNotCalled(t, "WriteChainStatuses", mock.Anything, mock.Anything)
}

// TestChainStatusBatcher_ConcurrentAccess drives writes, reads, disabled
// flushes and the ticker at the same time. Run it with -race.
func TestChainStatusBatcher_ConcurrentAccess(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)
	batcher.flushInterval = time.Millisecond

	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockManager.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	require.NoError(t, batcher.Start(t.Context()))

	const workers = 8
	const iterations = 200
	selectors := []protocol.ChainSelector{1, 2, 3, 4}

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			ctx := context.Background()
			for i := range iterations {
				selector := protocol.ChainSelector(i%len(selectors) + 1)
				// Every 10th write is disabled, which forces an immediate flush.
				disabled := i%10 == 0
				_ = batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
					status(selector, int64(worker*iterations+i), disabled),
				})
				_, _ = batcher.ReadChainStatuses(ctx, selectors)
			}
		}(w)
	}
	wg.Wait()

	require.NoError(t, batcher.Close())
}

// TestChainStatusBatcher_DoesNotShareCallerBigInt verifies that the batcher
// copies FinalizedBlockHeight, so a caller cannot change a buffered value.
func TestChainStatusBatcher_DoesNotShareCallerBigInt(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			recorder.record(statuses)
			return nil
		})

	height := big.NewInt(100)
	ctx := t.Context()
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{ChainSelector: 1, FinalizedBlockHeight: height},
	}))

	// The caller changes its own big.Int after the write.
	height.SetInt64(999)

	require.NoError(t, batcher.flush(ctx))
	batches := recorder.all()
	require.Equal(t, big.NewInt(100), batches[0][0].FinalizedBlockHeight)
}

// TestChainStatusBatcher_DisableIsSticky verifies that a checkpoint written after a
// finality violation cannot re-enable the chain. The source reader sends Disabled as
// false on every checkpoint, so without this guard a buffered or retried checkpoint
// would clear the flag up to one flush interval later.
func TestChainStatusBatcher_DisableIsSticky(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			recorder.record(statuses)
			return nil
		})

	ctx := t.Context()

	// Finality violation disables chain 1 and flushes at once.
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 0, true)}))
	require.Equal(t, 1, recorder.count())

	// A checkpoint for chain 1 arrives afterwards, carrying Disabled false.
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 900, false)}))
	require.NoError(t, batcher.flush(ctx))

	// No batch may ever carry chain 1 with Disabled false.
	for _, batch := range recorder.all() {
		for _, s := range batch {
			if s.ChainSelector == 1 {
				require.True(t, s.Disabled, "chain 1 must never be written as enabled")
			}
		}
	}
}

// TestChainStatusBatcher_StickyDisableDoesNotAffectOtherChains checks the guard is per chain.
func TestChainStatusBatcher_StickyDisableDoesNotAffectOtherChains(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			recorder.record(statuses)
			return nil
		})

	ctx := t.Context()
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 0, true)}))
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(2, 700, false)}))
	require.NoError(t, batcher.flush(ctx))

	last := recorder.all()[recorder.count()-1]
	require.Len(t, last, 1)
	require.Equal(t, protocol.ChainSelector(2), last[0].ChainSelector)
	require.False(t, last[0].Disabled)
}

// TestChainStatusBatcher_FailedFlushDoesNotResurrectEnabledStatus covers the restore
// path: a checkpoint drained before a disable must not come back after it.
func TestChainStatusBatcher_FailedFlushDoesNotResurrectEnabledStatus(t *testing.T) {
	batcher, _ := newTestBatcher(t)

	ctx := t.Context()
	// A checkpoint is buffered, then drained by a flush that is about to fail.
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 500, false)}))
	batcher.mu.Lock()
	drained := batcher.pending
	batcher.pending = make(map[protocol.ChainSelector]protocol.ChainStatusInfo)
	batcher.mu.Unlock()

	// The violation lands while that flush is in flight.
	batcher.mu.Lock()
	batcher.disabledChains[1] = true
	batcher.mu.Unlock()

	// The failed flush restores its drained statuses.
	batcher.restore(drained)

	batcher.mu.Lock()
	_, resurrected := batcher.pending[1]
	batcher.mu.Unlock()
	require.False(t, resurrected, "a stale enabled status must not return after a disable")
}

// TestChainStatusBatcher_DisableSurvivesOtherChainFailure checks that the disable
// write has its own failure domain. A buffered checkpoint for another chain that
// makes the database reject the batch must not stop the violating chain from being
// disabled.
func TestChainStatusBatcher_DisableSurvivesOtherChainFailure(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	recorder := &writeRecorder{}
	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
			// Any batch that carries chain 2 fails, as a bad row would.
			for _, s := range statuses {
				if s.ChainSelector == 2 {
					return errors.New("bad row for chain 2")
				}
			}
			recorder.record(statuses)
			return nil
		})

	ctx := t.Context()
	// Chain 2 sits in the buffer and will fail on write.
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(2, 400, false)}))

	// Chain 1 hits a finality violation. This must succeed despite chain 2.
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 0, true)}))

	batches := recorder.all()
	require.Len(t, batches, 1, "the disable is written on its own")
	require.Len(t, batches[0], 1)
	require.Equal(t, protocol.ChainSelector(1), batches[0][0].ChainSelector)
	require.True(t, batches[0][0].Disabled)
}

// TestChainStatusBatcher_DisableErrorIsReturned checks the caller still learns when
// the disable write itself fails.
func TestChainStatusBatcher_DisableErrorIsReturned(t *testing.T) {
	batcher, mockManager := newTestBatcher(t)

	mockManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		Return(errors.New("db down"))

	err := batcher.WriteChainStatuses(t.Context(), []protocol.ChainStatusInfo{status(1, 0, true)})
	require.Error(t, err)
	require.Contains(t, err.Error(), "db down")

	// It stays buffered so the ticker retries it.
	batcher.mu.Lock()
	pending, ok := batcher.pending[1]
	batcher.mu.Unlock()
	require.True(t, ok)
	require.True(t, pending.Disabled)
}
