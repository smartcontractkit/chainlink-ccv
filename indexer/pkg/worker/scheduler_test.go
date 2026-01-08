package worker

import (
	"context"
	"testing"
	"time"

	testmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	mocks "github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestScheduler_EnqueueImmediateAndDelayed(t *testing.T) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	require.NoError(t, err)

	// Immediate scheduler with BaseDelay=0 so backoff returns 0
	cfgImmediate := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	sImmediate, err := NewScheduler(lggr, cfgImmediate)
	require.NoError(t, err)

	msImmediate := mocks.NewMockIndexerStorage(t)

	immediate := &Task{ttl: time.Now().Add(time.Minute), attempt: 0, storage: msImmediate}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = sImmediate.Enqueue(ctx, immediate)
	require.NoError(t, err)

	// receive from Ready channel
	got := <-sImmediate.Ready()
	require.Equal(t, immediate, got)

	// Now test delayed scheduling with a separate scheduler
	cfgDelayed := config.SchedulerConfig{TickerInterval: 10, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	sDelayed, err := NewScheduler(lggr, cfgDelayed)
	require.NoError(t, err)

	msDelayed := mocks.NewMockIndexerStorage(t)
	delayed := &Task{ttl: time.Now().Add(time.Minute), attempt: 1, storage: msDelayed}

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
}

func TestScheduler_DLQOnTTLExpired(t *testing.T) {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	require.NoError(t, err)

	cfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 10, MaxDelay: 1000, VerificationVisibilityWindow: 60}
	s, err := NewScheduler(lggr, cfg)
	require.NoError(t, err)

	ms := mocks.NewMockIndexerStorage(t)
	// Expect UpdateMessageStatus to be called when task is sent to DLQ
	ms.On("UpdateMessageStatus", testmock.Anything, testmock.Anything, common.MessageTimeout, testmock.Anything).Return(nil)

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
