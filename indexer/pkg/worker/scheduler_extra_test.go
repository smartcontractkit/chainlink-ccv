package worker

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"

	mocks "github.com/smartcontractkit/chainlink/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

func TestScheduler_Enqueue_TTLExpired_DLQ(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	ms := mocks.NewMockIndexerStorage(t)
	t := &Task{ttl: time.Now().Add(-time.Minute), storage: ms}

	// expect UpdateMessageStatus to be called when sending to DLQ
	ms.On("UpdateMessageStatus", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err = s.Enqueue(context.Background(), t)
	require.Error(t, err)

	// should be placed on DLQ
	select {
	case got := <-s.DLQ():
		require.Equal(t, t, got)
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("timed out waiting for DLQ")
	}
}

func TestScheduler_Enqueue_PushesToHeapWhenDelayed(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 500, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	t := &Task{ttl: time.Now().Add(time.Minute)}

	err = s.Enqueue(context.Background(), t)
	require.NoError(t, err)

	// since BaseDelay > 0, the task should be pushed to the heap (delay > 0)
	s.mu.Lock()
	heapLen := s.delayHeap.Len()
	s.mu.Unlock()
	require.GreaterOrEqual(t, heapLen, 1)
}

func TestScheduler_Backoff_NegativeAttempt(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	d := s.backoff(-5)
	require.GreaterOrEqual(t, int(d.Milliseconds()), scfg.BaseDelay)
}

func TestScheduler_RunMovesDelayedToReady(t *testing.T) {
	lggr := logger.Test(t)
	scfg := config.SchedulerConfig{TickerInterval: 10, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, scfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create a task that will be delayed
	t := &Task{ttl: time.Now().Add(time.Minute)}
	err = s.Enqueue(context.Background(), t)
	require.NoError(t, err)

	// start scheduler run loop to process delayed heap
	s.Start(ctx)

	select {
	case got := <-s.Ready():
		require.Equal(t, t, got)
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for delayed task to become ready")
	}
}

