package evm

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
)

func TestEventPollerCache(t *testing.T) {
	t.Run("cache hit returns immediately", func(t *testing.T) {
		pollFn := func(start, end uint64) (map[eventKey]cciptestinterfaces.ExecutionStateChangedEvent, error) {
			return nil, nil
		}

		poller := newEventPoller(nil, zerolog.Nop(), "test", pollFn)

		key := eventKey{chainSelector: 1, msgNum: 100}
		expectedEvent := cciptestinterfaces.ExecutionStateChangedEvent{
			MessageID:     [32]byte{1, 2, 3},
			MessageNumber: 100,
			State:         cciptestinterfaces.MessageExecutionState(1),
		}
		poller.cachedEvents[key] = pollerResult[cciptestinterfaces.ExecutionStateChangedEvent]{event: expectedEvent}

		ctx := context.Background()
		resultCh := poller.register(ctx, 1, 100)

		select {
		case result := <-resultCh:
			require.NoError(t, result.err)
			require.Equal(t, expectedEvent.MessageID, result.event.MessageID)
			require.Equal(t, expectedEvent.MessageNumber, result.event.MessageNumber)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected to receive cached result immediately")
		}
	})

	t.Run("cache miss registers waiter and waits for context cancellation", func(t *testing.T) {
		pollFn := func(start, end uint64) (map[eventKey]cciptestinterfaces.ExecutionStateChangedEvent, error) {
			return nil, nil
		}

		poller := newEventPoller(nil, zerolog.Nop(), "test", pollFn)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		resultCh := poller.register(ctx, 1, 100)

		select {
		case result := <-resultCh:
			require.Error(t, result.err)
			require.Equal(t, context.DeadlineExceeded, result.err)
		case <-time.After(200 * time.Millisecond):
			t.Fatal("expected to timeout waiting for event")
		}
	})

	t.Run("multiple callers for same event get same channel", func(t *testing.T) {
		pollFn := func(start, end uint64) (map[eventKey]cciptestinterfaces.ExecutionStateChangedEvent, error) {
			return nil, nil
		}

		poller := newEventPoller(nil, zerolog.Nop(), "test", pollFn)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resultCh1 := poller.register(ctx, 1, 100)
		resultCh2 := poller.register(ctx, 1, 100)

		require.Equal(t, resultCh1, resultCh2, "multiple callers for same key should get the same channel")
	})

	t.Run("cache hit after first caller gets cached result", func(t *testing.T) {
		pollFn := func(start, end uint64) (map[eventKey]cciptestinterfaces.ExecutionStateChangedEvent, error) {
			return nil, nil
		}

		poller := newEventPoller(nil, zerolog.Nop(), "test", pollFn)

		key := eventKey{chainSelector: 1, msgNum: 100}
		expectedEvent := cciptestinterfaces.ExecutionStateChangedEvent{
			MessageID:     [32]byte{1, 2, 3},
			MessageNumber: 100,
		}
		poller.cachedEvents[key] = pollerResult[cciptestinterfaces.ExecutionStateChangedEvent]{event: expectedEvent}

		ctx := context.Background()
		resultCh1 := poller.register(ctx, 1, 100)
		resultCh2 := poller.register(ctx, 1, 100)

		result1 := <-resultCh1
		result2 := <-resultCh2

		require.NoError(t, result1.err)
		require.NoError(t, result2.err)
		require.Equal(t, expectedEvent.MessageID, result1.event.MessageID)
		require.Equal(t, expectedEvent.MessageID, result2.event.MessageID)
	})
}

func TestEventPollerMessageSent(t *testing.T) {
	t.Run("cache hit returns immediately for message sent events", func(t *testing.T) {
		pollFn := func(start, end uint64) (map[eventKey]cciptestinterfaces.MessageSentEvent, error) {
			return nil, nil
		}

		poller := newEventPoller(nil, zerolog.Nop(), "test", pollFn)

		key := eventKey{chainSelector: 1, msgNum: 100}
		expectedEvent := cciptestinterfaces.MessageSentEvent{
			MessageID: [32]byte{1, 2, 3},
		}
		poller.cachedEvents[key] = pollerResult[cciptestinterfaces.MessageSentEvent]{event: expectedEvent}

		ctx := context.Background()
		resultCh := poller.register(ctx, 1, 100)

		select {
		case result := <-resultCh:
			require.NoError(t, result.err)
			require.Equal(t, expectedEvent.MessageID, result.event.MessageID)
			require.Equal(t, expectedEvent.Sender, result.event.Sender)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected to receive cached result immediately")
		}
	})
}
