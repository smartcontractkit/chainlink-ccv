package executor

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestCoordinator_dataNotReadyBackoff(t *testing.T) {
	t.Parallel()

	ec := &Coordinator{dataNotReadyRetryInterval: time.Second}
	stagger := 30 * time.Second

	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{name: "first attempt", attempt: 1, want: time.Second},
		{name: "second attempt", attempt: 2, want: 2 * time.Second},
		{name: "third attempt", attempt: 3, want: 4 * time.Second},
		{name: "capped at stagger", attempt: 10, want: stagger},
		{name: "zero attempt normalized", attempt: 0, want: time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ec.dataNotReadyBackoff(tc.attempt, stagger)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestCoordinator_dataNotReadyBackoff_Overflow(t *testing.T) {
	t.Parallel()

	// A large base interval overflows the shift well before the attempt clamp.
	ec := &Coordinator{dataNotReadyRetryInterval: time.Hour}
	require.Equal(t, time.Hour, ec.dataNotReadyBackoff(30, 0), "overflow with no cap must fall back to the base interval")
	require.Equal(t, 30*time.Second, ec.dataNotReadyBackoff(30, 30*time.Second), "overflow with a cap must return the cap")
}

// A message that reaches a terminal state quickly after dispatch must not leave
// an entry in the in-flight map once the worker is done with it.
func TestCoordinator_InFlightEmptyAfterTerminalDispatch(t *testing.T) {
	lggr, hook := logger.TestObserved(t, zapcore.DebugLevel)
	currentTime := time.Now().UTC()
	// Time is past the message expiry so the first dispatch is terminal (expired).
	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().Return(currentTime.Add(2 * time.Second)).Maybe()

	testMessage := common.MessageWithMetadata{
		Message: protocol.Message{
			DestChainSelector:   1,
			SourceChainSelector: 2,
			SequenceNumber:      1,
		},
		Metadata: common.MessageMetadata{
			IngestionTimestamp: currentTime,
		},
	}

	results := make(chan common.MessageWithMetadata, 1)
	results <- testMessage
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil)

	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)
	mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()

	leaderElector := mocks.NewMockLeaderElector(t)
	leaderElector.EXPECT().IsExecutorForChain(mock.Anything).Return(true).Maybe()
	leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).Return(currentTime, nil).Maybe()
	leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(time.Second, nil).Maybe()

	ec, err := NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		leaderElector,
		monitoring.NewNoopExecutorMonitoring(),
		time.Second,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)

	require.NoError(t, ec.Start(t.Context()))
	defer func() { require.NoError(t, ec.Close()) }()

	found := func(s string) bool {
		for _, entry := range hook.All() {
			if strings.Contains(fmt.Sprintf("%+v", entry), s) {
				return true
			}
		}
		return false
	}
	require.Eventuallyf(t, func() bool {
		return found("message has expired")
	}, 3*time.Second, 50*time.Millisecond, "timed out waiting for the message to expire")

	require.Eventuallyf(t, func() bool {
		ec.inFlightMu.RLock()
		defer ec.inFlightMu.RUnlock()
		return len(ec.inFlight) == 0
	}, 3*time.Second, 10*time.Millisecond, "in-flight map not empty after terminal dispatch")
}

// When Close lands while the processing loop is mid-dispatch, the undispatched
// payload must be requeued onto the heap rather than dropped.
func TestCoordinator_ShutdownMidDispatchRequeuesToHeap(t *testing.T) {
	lggr := logger.Test(t)
	currentTime := time.Now().UTC()
	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().Return(currentTime).Maybe()

	seqNum := uint64(0)
	messageGenerator := func() common.MessageWithMetadata {
		seqNum++
		return common.MessageWithMetadata{
			Message: protocol.Message{
				DestChainSelector:   1,
				SourceChainSelector: 2,
				SequenceNumber:      protocol.SequenceNumber(seqNum),
			},
			Metadata: common.MessageMetadata{
				IngestionTimestamp: currentTime,
			},
		}
	}

	msg1 := messageGenerator()
	msg2 := messageGenerator()
	results := make(chan common.MessageWithMetadata, 2)
	results <- msg1
	results <- msg2
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil)

	handlerBlockedHandle := make(chan struct{})
	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)
	mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockExecutor.EXPECT().HandleMessage(mock.Anything, mock.Anything).Run(func(ctx context.Context, msg protocol.Message) {
		close(handlerBlockedHandle)
		<-ctx.Done()
	}).Return(false, context.Canceled)

	leaderElector := mocks.NewMockLeaderElector(t)
	leaderElector.EXPECT().IsExecutorForChain(mock.Anything).Return(true).Maybe()
	leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).Return(currentTime, nil).Maybe()
	leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(time.Second, nil).Maybe()

	ec, err := NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		leaderElector,
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)

	require.NoError(t, ec.Start(t.Context()))

	// The single worker is busy with the first message; the second has been popped
	// from the heap and is stuck mid-dispatch on the unbuffered worker channel.
	require.Eventuallyf(t, func() bool {
		select {
		case <-handlerBlockedHandle:
			return ec.delayedMessageHeap.Len() == 0
		default:
			return false
		}
	}, 5*time.Second, 50*time.Millisecond, "timed out waiting for mid-dispatch state")

	require.NoError(t, ec.Close())

	require.Equal(t, 1, ec.delayedMessageHeap.Len(), "undispatched payload was not requeued onto the heap")
	require.True(t,
		ec.delayedMessageHeap.Has(msg1.Message.MustMessageID()) || ec.delayedMessageHeap.Has(msg2.Message.MustMessageID()),
		"requeued payload is not one of the test messages")

	ec.inFlightMu.RLock()
	defer ec.inFlightMu.RUnlock()
	require.Empty(t, ec.inFlight, "in-flight map not empty after shutdown")
}
