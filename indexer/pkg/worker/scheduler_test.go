package worker

import (
	"container/heap"
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestScheduler_EnqueueImmediateAndDelayed verifies two behaviors:
//  1. Immediate fast-path: when a Task's computed delay is zero (runAt == now),
//     Enqueue should deliver it directly to the Scheduler's Ready channel
//     without waiting for the scheduler ticker. This ensures low-latency delivery
//     for immediate work.
//  2. Delayed scheduling: when a Task has a positive delay, Enqueue should push
//     it onto the scheduler's delay heap and the task should only be moved to
//     the Ready channel when the scheduler's ticker triggers PopAllReady().
func TestScheduler_EnqueueImmediateAndDelayed(t *testing.T) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	require.NoError(t, err)

	// Subtest: immediate fast-path
	t.Run("Immediate", func(t *testing.T) {
		cfgImmediate := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 1000, VerificationVisibilityWindow: 60}
		sImmediate, err := NewScheduler(lggr, cfgImmediate)
		require.NoError(t, err)

		msImmediate := mocks.NewMockIndexerStorage(t)
		immediate := &Task{ttl: time.Now().Add(time.Minute), attempt: 0, storage: msImmediate}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		err = sImmediate.Enqueue(ctx, immediate)
		require.NoError(t, err)

		got := <-sImmediate.Ready()
		require.Equal(t, immediate, got)
	})

	// Subtest: delayed scheduling onto the heap
	t.Run("Delayed", func(t *testing.T) {
		cfgDelayed := config.SchedulerConfig{TickerInterval: 10, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
		sDelayed, err := NewScheduler(lggr, cfgDelayed)
		require.NoError(t, err)

		msDelayed := mocks.NewMockIndexerStorage(t)
		delayed := &Task{ttl: time.Now().Add(time.Minute), attempt: 1, storage: msDelayed}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// start scheduler to process the heap
		sDelayed.Start(ctx)
		defer sDelayed.Stop()

		err = sDelayed.Enqueue(ctx, delayed)
		require.NoError(t, err)

		select {
		case g := <-sDelayed.Ready():
			require.Equal(t, delayed, g)
		case <-time.After(1 * time.Second):
			t.Fatalf("timed out waiting for delayed task")
		}
	})
}

// TestScheduler_DLQOnTTLExpired verifies that tasks whose TTL has already
// expired are sent to the scheduler's DLQ and that Enqueue calls
// UpdateMessageStatus(...) on the storage with MessageTimeout. The test
// asserts the task is delivered to the DLQ and that the storage interaction
// occurs (via the mock expectation).
func TestScheduler_DLQOnTTLExpired(t *testing.T) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	require.NoError(t, err)

	cfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, cfg)
	require.NoError(t, err)

	ms := mocks.NewMockIndexerStorage(t)
	// Expect UpdateMessageStatus to be called when task is sent to DLQ
	ms.On("UpdateMessageStatus", mock.Anything, mock.Anything, common.MessageTimeout, mock.Anything).Return(nil)

	expired := &Task{ttl: time.Now().Add(-time.Minute), attempt: 10, storage: ms}

	ctx := context.Background()
	err = s.Enqueue(ctx, expired)
	require.Error(t, err)

	// DLQ channel should receive the task
	select {
	case got := <-s.DLQ():
		require.Equal(t, expired, got)
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timed out waiting for DLQ")
	}

	// mock expectations will be asserted on test cleanup
}

// TestScheduler_Backoff_NegativeAttempt validates backoff calculation lower-bounds
// the delay when an invalid negative attempt value is provided.
func TestScheduler_Backoff_NegativeAttempt(t *testing.T) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	require.NoError(t, err)

	scfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	d := s.backoff(-5)
	require.GreaterOrEqual(t, int(d.Milliseconds()), scfg.BaseDelay)
}

// TestScheduler_Enqueue_TTLExpired_DLQ asserts Enqueue returns an error for
// tasks whose TTL is already expired and that such tasks are placed on DLQ.
func TestScheduler_Enqueue_TTLExpired_DLQ(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	ms := mocks.NewMockIndexerStorage(t)
	tsk := &Task{ttl: time.Now().Add(-time.Minute), storage: ms}

	// expect UpdateMessageStatus to be called when sending to DLQ
	ms.On("UpdateMessageStatus", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err = s.Enqueue(context.Background(), tsk)
	require.Error(t, err)

	// should be placed on DLQ
	select {
	case got := <-s.DLQ():
		require.Equal(t, tsk, got)
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("timed out waiting for DLQ")
	}
}

// TestScheduler_Enqueue_PushesToHeapWhenDelayed verifies tasks with non-zero delay
// are pushed to the scheduler's heap instead of Ready.
func TestScheduler_Enqueue_PushesToHeapWhenDelayed(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 500, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	tsk := &Task{ttl: time.Now().Add(time.Minute)}

	err = s.Enqueue(context.Background(), tsk)
	require.NoError(t, err)

	// since BaseDelay > 0, the task should be pushed to the heap (delay > 0)
	s.mu.Lock()
	heapLen := s.delayHeap.Len()
	s.mu.Unlock()
	require.GreaterOrEqual(t, heapLen, 1)
}

// TestScheduler_RunMovesDelayedToReady ensures the scheduler's run loop moves
// delayed tasks from the heap to the Ready channel on tick.
func TestScheduler_RunMovesDelayedToReady(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 10, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create a task that will be delayed
	tsk := &Task{ttl: time.Now().Add(time.Minute)}
	err = s.Enqueue(context.Background(), tsk)
	require.NoError(t, err)

	// start scheduler run loop to process delayed heap
	s.Start(ctx)

	select {
	case got := <-s.Ready():
		require.Equal(t, tsk, got)
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for delayed task to become ready")
	}
}

func TestScheduler_RunDoesNotLeakGoroutinesUnderBurst(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 10, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	const taskCount = 200

	s.mu.Lock()
	for range taskCount {
		heap.Push(s.delayHeap, &Task{
			ttl:   time.Now().Add(time.Minute),
			runAt: time.Now().Add(-time.Second),
		})
	}
	s.mu.Unlock()

	runtime.GC()
	runtime.Gosched()
	baselineGoroutines := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.Start(ctx)

	// Do NOT consume from Ready — simulate backpressure from a saturated worker pool.
	time.Sleep(100 * time.Millisecond)

	peakGoroutines := runtime.NumGoroutine()

	maxAllowedGrowth := 10
	require.LessOrEqual(t, peakGoroutines-baselineGoroutines, maxAllowedGrowth,
		"goroutine count grew by %d (from %d to %d); expected bounded growth under backpressure",
		peakGoroutines-baselineGoroutines, baselineGoroutines, peakGoroutines)
}
