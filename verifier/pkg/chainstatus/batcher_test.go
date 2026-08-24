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

func newTestBatcher(t *testing.T) (*ChainStatusBatcher, *mocks.MockChainStatusManager) {
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
	// Chain 1 is buffered and must go out with the immediate flush of chain 2.
	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(1, 100, false)}))
	require.Equal(t, 0, recorder.count())

	require.NoError(t, batcher.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{status(2, 0, true)}))

	batches := recorder.all()
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 2)

	byChain := make(map[protocol.ChainSelector]protocol.ChainStatusInfo)
	for _, s := range batches[0] {
		byChain[s.ChainSelector] = s
	}
	require.False(t, byChain[1].Disabled)
	require.True(t, byChain[2].Disabled)
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
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < iterations; i++ {
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
