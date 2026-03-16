package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery/internal"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// buildIsolatedDiscovery creates an AggregatorMessageDiscovery wired to a MockReader
// that will emit numMessages messages.  Start() is NOT called, making it safe to invoke
// callReader() or consumeReader() directly in unit tests.
func buildIsolatedDiscovery(
	t *testing.T,
	priority int,
	notifier *PrimaryWriteNotifier,
	numMessages int,
) *AggregatorMessageDiscovery {
	t.Helper()

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	reg := registry.NewVerifierRegistry()

	ts := &testSetup{capturedSeqNumbers: make(map[string]int)}
	store := newMockStorage(t, ts)

	mockRdr := internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: false,
		MaxMessages:        numMessages,
		MessageGenerator: func(n int) common.VerifierResultWithMetadata {
			return createTestCCVData(n, time.Now().UnixMilli(), 1, 2)
		},
	})
	resilientRdr := readers.NewResilientReader(mockRdr, lggr, readers.DefaultResilienceConfig())

	tp := mocks.NewMockTimeProvider(t)
	tp.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	disc, err := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithRegistry(reg),
		WithTimeProvider(tp),
		WithMonitoring(mon),
		WithStorage(store),
		WithAggregator(resilientRdr),
		WithConfig(defaultTestConfig()),
		WithDiscoveryPriority(priority),
		WithPrimaryWriteNotifier(notifier),
	)
	require.NoError(t, err)
	return disc.(*AggregatorMessageDiscovery)
}

// TestClose_DoesNotDeadlockWhenChannelHasNoConsumer is the end-to-end regression
// test for the shutdown deadlock fix.
//
// The problematic sequence, before the fix:
//  1. run() enters callReader, reads data, persists it, then tries to emit it
//     to the unbuffered messageCh with a plain blocking send.
//  2. The parent context is canceled, so enqueueMessages (the only consumer) exits.
//  3. Nobody reads from messageCh — the blocking send in callReader hangs forever.
//  4. run() never calls wg.Done(), so Close()'s wg.Wait() never returns.
func TestClose_DoesNotDeadlockWhenChannelHasNoConsumer(t *testing.T) {
	cfg := config.DiscoveryConfig{PollInterval: 20, Timeout: 5000}
	ts := setupMessageDiscoveryTestNoTimeout(t, cfg)

	// Continuous supply of messages keeps callReader busy trying to send to messageCh.
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: false,
		MaxMessages:        100,
		MessageGenerator: func(n int) common.VerifierResultWithMetadata {
			return createTestCCVData(n, time.Now().UnixMilli(), 1, 2)
		},
	})
	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	// Start discovery but deliberately do NOT drain messageCh — this recreates
	// the scenario where the worker-pool consumer has already exited.
	_ = ts.Discovery.Start(ts.Context)

	// Let the run goroutine reach the point where it blocks on messageCh.
	time.Sleep(60 * time.Millisecond)

	// Simulate system shutdown: cancel the context.
	ts.Cancel()

	closeDone := make(chan struct{})
	go func() {
		_ = ts.Discovery.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		// Pass: Close() returned cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("Close() deadlocked — run() is stuck writing to messageCh with no consumer")
	}
}

// TestCallReader_ContextAwareSendReturnsOnCancellation is the unit-level regression
// test for the context-aware messageCh write.  It cancels the context precisely when
// PersistDiscoveryBatch returns so that callReader is in the send phase — with a
// canceled context and no consumer on messageCh — when it attempts the write.
//
// Without the fix the plain `a.messageCh <- msg` blocks forever.
// With the fix the context-aware select exits immediately.
func TestCallReader_ContextAwareSendReturnsOnCancellation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	reg := registry.NewVerifierRegistry()

	persistCalled := make(chan struct{}, 1)
	store := mocks.NewMockIndexerStorage(t)
	store.EXPECT().PersistDiscoveryBatch(mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ common.DiscoveryBatch) {
			// Cancel the context inside persist so that by the time callReader
			// reaches the send loop the context is already done.
			cancelCtx()
			persistCalled <- struct{}{}
		}).Return(nil).Once()

	mockRdr := internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: false,
		MaxMessages:        1,
		MessageGenerator: func(n int) common.VerifierResultWithMetadata {
			return createTestCCVData(n, time.Now().UnixMilli(), 1, 2)
		},
	})
	resilientRdr := readers.NewResilientReader(mockRdr, lggr, readers.DefaultResilienceConfig())

	tp := mocks.NewMockTimeProvider(t)
	tp.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	disc, err := NewAggregatorMessageDiscovery(
		WithLogger(lggr), WithRegistry(reg), WithTimeProvider(tp),
		WithMonitoring(mon), WithStorage(store), WithAggregator(resilientRdr),
		WithConfig(defaultTestConfig()),
	)
	require.NoError(t, err)

	aggDisc := disc.(*AggregatorMessageDiscovery)
	aggDisc.discoveryPriority = 0
	// Unbuffered channel with no reader — the exact deadlock condition.
	aggDisc.messageCh = make(chan common.VerifierResultWithMetadata)

	callReaderDone := make(chan struct{})
	go func() {
		_, _ = aggDisc.callReader(ctx)
		close(callReaderDone)
	}()

	// Wait until persist was called (and thus the context was canceled).
	select {
	case <-persistCalled:
	case <-time.After(1 * time.Second):
		t.Fatal("PersistDiscoveryBatch was never called")
	}

	// callReader must exit — without the fix it blocks on messageCh indefinitely.
	select {
	case <-callReaderDone:
		// Pass: callReader returned without blocking.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("callReader blocked writing to messageCh after context was canceled")
	}
}

// TestPrimaryWriteNotifier_NotifyUnblocksAllWaiters verifies that a single Notify()
// call immediately unblocks every goroutine currently waiting on WaitCh().
func TestPrimaryWriteNotifier_NotifyUnblocksAllWaiters(t *testing.T) {
	notifier := NewPrimaryWriteNotifier()

	const numWaiters = 5
	started := make(chan struct{}, numWaiters)
	unblocked := make(chan struct{}, numWaiters)

	for range numWaiters {
		go func() {
			waitCh := notifier.WaitCh()
			started <- struct{}{}
			<-waitCh
			unblocked <- struct{}{}
		}()
	}

	// Wait for every goroutine to call WaitCh() before we notify.
	for range numWaiters {
		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("goroutine did not reach WaitCh() in time")
		}
	}

	// Sanity check: nobody should be unblocked before Notify().
	select {
	case <-unblocked:
		t.Fatal("a waiter was unblocked before Notify() was called")
	default:
	}

	notifier.Notify()

	for i := range numWaiters {
		select {
		case <-unblocked:
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("waiter %d was not unblocked after Notify()", i)
		}
	}
}

// TestPrimaryWriteNotifier_FreshChannelAfterEachNotify verifies that after Notify()
// the notifier provides a brand-new, open channel via WaitCh() — so that a signal from
// tick N cannot accidentally unblock a waiter that starts listening in tick N+1.
func TestPrimaryWriteNotifier_FreshChannelAfterEachNotify(t *testing.T) {
	notifier := NewPrimaryWriteNotifier()

	ch1 := notifier.WaitCh()
	notifier.Notify()

	// ch1 must be closed after the first Notify().
	select {
	case <-ch1:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ch1 should be closed after first Notify()")
	}

	// ch2, obtained after the first Notify(), must NOT be pre-closed.
	ch2 := notifier.WaitCh()
	select {
	case <-ch2:
		t.Fatal("ch2 must not be pre-closed; old signals must not leak across ticks")
	default:
	}

	notifier.Notify()

	// ch2 must be closed after the second Notify().
	select {
	case <-ch2:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ch2 should be closed after second Notify()")
	}
}

// TestCallReader_PrimaryNotifiesAfterSuccessfulWrite verifies that the primary source
// (priority 0) calls Notify() on the PrimaryWriteNotifier after a successful read and
// persist, so waiting secondary sources are unblocked.
func TestCallReader_PrimaryNotifiesAfterSuccessfulWrite(t *testing.T) {
	notifier := NewPrimaryWriteNotifier()

	aggDisc := buildIsolatedDiscovery(t, 0, notifier, 1)
	// Buffered so the send in callReader doesn't block.
	aggDisc.messageCh = make(chan common.VerifierResultWithMetadata, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Capture the channel before calling callReader so we don't miss the deferred
	// Notify() if callReader returns before the goroutine reaches <-waitCh.
	waitCh := notifier.WaitCh()
	notified := make(chan struct{})
	go func() {
		<-waitCh
		close(notified)
	}()

	_, err := aggDisc.callReader(ctx)
	require.NoError(t, err)

	select {
	case <-notified:
		// Pass: primary notified after successful write.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("primary did not notify secondary sources after a successful write")
	}
}

// TestCallReader_PrimaryNotifiesAfterReadError verifies that the defer-based Notify()
// fires even when ReadCCVData returns an error — so secondary sources are never left
// waiting their full delay when the primary's aggregator is unavailable.
func TestCallReader_PrimaryNotifiesAfterReadError(t *testing.T) {
	notifier := NewPrimaryWriteNotifier()

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	reg := registry.NewVerifierRegistry()
	ts := &testSetup{capturedSeqNumbers: make(map[string]int)}
	store := newMockStorage(t, ts)

	tp := mocks.NewMockTimeProvider(t)
	tp.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	// Reader that immediately returns an error.
	mockRdr := internal.NewMockReader(internal.MockReaderConfig{
		ErrorAfterCalls: 1,
		Error:           errors.New("aggregator down"),
	})
	resilientRdr := readers.NewResilientReader(mockRdr, lggr, readers.DefaultResilienceConfig())

	disc, err := NewAggregatorMessageDiscovery(
		WithLogger(lggr), WithRegistry(reg), WithTimeProvider(tp),
		WithMonitoring(mon), WithStorage(store), WithAggregator(resilientRdr),
		WithConfig(defaultTestConfig()),
		WithDiscoveryPriority(0),
		WithPrimaryWriteNotifier(notifier),
	)
	require.NoError(t, err)
	aggDisc := disc.(*AggregatorMessageDiscovery)
	aggDisc.messageCh = make(chan common.VerifierResultWithMetadata, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Capture the channel before calling callReader so we don't miss the deferred
	// Notify() if callReader returns before the goroutine reaches <-waitCh.
	waitCh := notifier.WaitCh()
	notified := make(chan struct{})
	go func() {
		<-waitCh
		close(notified)
	}()

	// callReader will return an error, but defer must still fire Notify().
	_, _ = aggDisc.callReader(ctx)

	select {
	case <-notified:
		// Pass: Notify() was deferred and fired even on the error path.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("primary did not notify after a read error — secondary sources would wait the full delay unnecessarily")
	}
}

// TestCallReader_PrimaryNotifiesAfterCircuitBreakerOpen verifies that the deferred
// Notify() fires when the circuit breaker is open and callReader returns early without
// writing anything.
func TestCallReader_PrimaryNotifiesAfterCircuitBreakerOpen(t *testing.T) {
	notifier := NewPrimaryWriteNotifier()

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	reg := registry.NewVerifierRegistry()
	ts := &testSetup{capturedSeqNumbers: make(map[string]int)}
	store := newMockStorage(t, ts)

	tp := mocks.NewMockTimeProvider(t)
	tp.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	mockRdr := internal.NewMockReader(internal.MockReaderConfig{
		ErrorAfterCalls: 1,
		Error:           errors.New("aggregator down"),
	})

	// Open circuit breaker immediately after the first failure.
	cbCfg := readers.DefaultResilienceConfig()
	cbCfg.FailureThreshold = 1
	cbCfg.CircuitBreakerDelay = 10 * time.Second // keep it open for the duration of the test
	resilientRdr := readers.NewResilientReader(mockRdr, lggr, cbCfg)

	disc, err := NewAggregatorMessageDiscovery(
		WithLogger(lggr), WithRegistry(reg), WithTimeProvider(tp),
		WithMonitoring(mon), WithStorage(store), WithAggregator(resilientRdr),
		WithConfig(defaultTestConfig()),
		WithDiscoveryPriority(0),
		WithPrimaryWriteNotifier(notifier),
	)
	require.NoError(t, err)
	aggDisc := disc.(*AggregatorMessageDiscovery)
	aggDisc.messageCh = make(chan common.VerifierResultWithMetadata, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// First call opens the circuit breaker.
	_, _ = aggDisc.callReader(ctx)

	// Obtain the wait channel BEFORE the second callReader call.  If we spawned a goroutine
	// that called WaitCh() concurrently with callReader, there is a race: the deferred
	// Notify() might fire before the goroutine calls WaitCh(), causing it to receive a
	// fresh un-closed channel and miss the signal.  Capturing the channel on the main
	// goroutine first avoids this: even if Notify() fires before the goroutine reaches
	// <-waitCh, the channel is already closed and the receive returns immediately.
	waitCh := notifier.WaitCh()
	notified := make(chan struct{})
	go func() {
		<-waitCh
		close(notified)
	}()

	// Second call: circuit breaker is now open; callReader should return false, nil
	// and still call Notify() via defer.
	found, callErr := aggDisc.callReader(ctx)
	assert.False(t, found)
	assert.NoError(t, callErr)

	select {
	case <-notified:
		// Pass: Notify() fired even when the circuit breaker was open.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("primary did not notify when circuit breaker was open — secondary sources would wait the full delay unnecessarily")
	}
}

// TestCallReader_SecondaryUnblocksEarlyWhenPrimarySignals verifies that a secondary
// source exits the priority delay as soon as the primary signals completion, rather
// than waiting out the full delay.
func TestCallReader_SecondaryUnblocksEarlyWhenPrimarySignals(t *testing.T) {
	notifier := NewPrimaryWriteNotifier()

	aggDisc := buildIsolatedDiscovery(t, 1 /* priority */, notifier, 1 /* numMessages */)
	aggDisc.messageCh = make(chan common.VerifierResultWithMetadata, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Simulate the primary finishing its write after a short head-start, well before
	// the 5-second delay would expire.
	go func() {
		time.Sleep(30 * time.Millisecond)
		notifier.Notify()
	}()

	start := time.Now()
	_, err := aggDisc.callReader(ctx)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, 1*time.Second,
		"secondary source should proceed as soon as primary signals, not wait the full 5s delay")
}

// TestCallReader_SecondaryExitsViaContextWithoutNotifier verifies backward
// compatibility: a secondary source configured without a PrimaryWriteNotifier still
// exits the delay via context cancellation and does not block indefinitely.
func TestCallReader_SecondaryExitsViaContextWithoutNotifier(t *testing.T) {
	aggDisc := buildIsolatedDiscovery(t, 1 /* priority */, nil /* no notifier */, 1)
	aggDisc.messageCh = make(chan common.VerifierResultWithMetadata, 10)

	// Context times out at 100 ms — well before the 5 s priority delay.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	aggDisc.consumeReader(ctx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 1*time.Second,
		"secondary without a notifier should still exit via ctx cancellation, not wait the full 5s delay")
}
