package batcher

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBatcher_RetryBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 10
	maxWait := 50 * time.Millisecond // Short maxWait so retry ticker runs every 100ms

	b := NewBatcher[int](maxSize, maxWait, 10)
	b.Start(ctx)
	batcher := b
	t.Cleanup(func() {
		cancel()
		_ = batcher.Close()
	})

	// Add some items to retry with a short delay
	itemsToRetry := []int{1, 2, 3}
	retryDelay := 50 * time.Millisecond

	err := batcher.Retry(retryDelay, itemsToRetry...)
	require.NoError(t, err)

	// Items should be retried after the delay
	// Wait for retry to be processed (retry ticker is 2*maxWait = 100ms)
	time.Sleep(retryDelay + 2*maxWait + 100*time.Millisecond)

	// Should receive a batch with the retried items
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(itemsToRetry))
		require.Equal(t, itemsToRetry, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items to be flushed")
	}
}

func TestBatcher_RetryWithSizeBasedFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	maxSize := 5
	maxWait := 50 * time.Millisecond // Short wait for retry ticker

	b := NewBatcher[int](maxSize, maxWait, 10)
	b.Start(ctx)
	batcher := b
	t.Cleanup(func() {
		cancel()
		_ = batcher.Close()
	})

	// Retry exactly maxSize items with a short delay
	itemsToRetry := []int{10, 20, 30, 40, 50}
	retryDelay := 50 * time.Millisecond

	err := batcher.Retry(retryDelay, itemsToRetry...)
	require.NoError(t, err)

	// Wait for retry delay and processing time (retry ticker is 2*maxWait = 100ms)
	time.Sleep(retryDelay + 2*maxWait + 100*time.Millisecond)

	// Should receive a batch immediately when retry buffer moves to main buffer
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, maxSize)
		require.Equal(t, itemsToRetry, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items to trigger size-based flush")
	}
}

func TestBatcher_RetryMixedWithAdd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	maxSize := 10
	maxWait := 100 * time.Millisecond

	b := NewBatcher[int](maxSize, maxWait, 10)
	b.Start(ctx)
	batcher := b
	t.Cleanup(func() {
		cancel()
		_ = batcher.Close()
	})

	// Add some items immediately
	immediateItems := []int{1, 2, 3}
	for _, item := range immediateItems {
		err := batcher.Add(item)
		require.NoError(t, err)
	}

	// Schedule retry items with a delay
	retryItems := []int{4, 5, 6}
	retryDelay := 50 * time.Millisecond

	err := batcher.Retry(retryDelay, retryItems...)
	require.NoError(t, err)

	// First batch: immediate items should flush after maxWait
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(immediateItems))
		require.Equal(t, immediateItems, batch.Items)
	case <-time.After(maxWait + 100*time.Millisecond):
		t.Fatal("expected immediate items to be flushed")
	}

	// Wait for retry items to be processed (retry ticker is 2*maxWait = 200ms)
	time.Sleep(retryDelay + 2*maxWait + 100*time.Millisecond)

	// Second batch: retried items
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(retryItems))
		require.Equal(t, retryItems, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items to be flushed")
	}
}

func TestBatcher_RetryMultipleBatchesWithDifferentDelays(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	maxSize := 10
	maxWait := 50 * time.Millisecond

	b := NewBatcher[int](maxSize, maxWait, 10)
	b.Start(ctx)
	batcher := b

	// Schedule first retry batch with short delay
	firstRetry := []int{1, 2}
	firstDelay := 100 * time.Millisecond

	err := batcher.Retry(firstDelay, firstRetry...)
	require.NoError(t, err)

	// Schedule second retry batch with longer delay
	secondRetry := []int{3, 4}
	secondDelay := 300 * time.Millisecond

	err = batcher.Retry(secondDelay, secondRetry...)
	require.NoError(t, err)

	// Wait for first retry to be processed (retry ticker is 2*maxWait = 100ms)
	time.Sleep(firstDelay + 2*maxWait + 100*time.Millisecond)

	// Should receive first batch
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(firstRetry))
		require.Equal(t, firstRetry, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected first retry batch to be flushed")
	}

	// Wait for second retry to be processed
	time.Sleep(secondDelay - firstDelay + 100*time.Millisecond)

	// Should receive second batch
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(secondRetry))
		require.Equal(t, secondRetry, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected second retry batch to be flushed")
	}

	// Cancel context then close batcher
	cancel()
	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_RetryPreservesOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	maxSize := 10
	maxWait := 100 * time.Millisecond

	b := NewBatcher[int](maxSize, maxWait, 10)
	b.Start(ctx)
	batcher := b

	// Retry items in specific order
	retryItems := []int{5, 3, 9, 1, 7}
	retryDelay := 50 * time.Millisecond

	err := batcher.Retry(retryDelay, retryItems...)
	require.NoError(t, err)

	// Wait for retry to be processed (retry ticker is 2*maxWait = 200ms)
	time.Sleep(retryDelay + 2*maxWait + 100*time.Millisecond)

	// Should receive items in the same order they were retried
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Equal(t, retryItems, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items to be flushed")
	}

	// Cancel context then close batcher
	cancel()
	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_RetryEmptySlice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	maxSize := 10
	maxWait := 100 * time.Millisecond

	b := NewBatcher[int](maxSize, maxWait, 10)
	b.Start(ctx)
	batcher := b

	// Retry empty slice should not cause issues
	err := batcher.Retry(50 * time.Millisecond)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(200 * time.Millisecond)

	// Should not receive any batch
	select {
	case batch := <-batcher.OutChannel():
		t.Fatalf("unexpected batch received with %d items", len(batch.Items))
	case <-time.After(100 * time.Millisecond):
		// Correct - no batch
	}

	// Cancel context then close batcher
	cancel()
	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_RetryZeroDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	maxSize := 10
	maxWait := 50 * time.Millisecond // Short maxWait so retry ticker runs every 100ms

	b := NewBatcher[int](maxSize, maxWait, 10)
	b.Start(ctx)
	batcher := b

	// Retry with zero delay - should be processed on next retry ticker
	retryItems := []int{1, 2, 3}

	err := batcher.Retry(0, retryItems...)
	require.NoError(t, err)

	// Wait for retry processing (retry ticker is 2*maxWait = 100ms)
	time.Sleep(2*maxWait + 100*time.Millisecond)

	// Should receive batch with retried items
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Equal(t, retryItems, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items with zero delay to be flushed")
	}

	// Cancel context then close batcher
	cancel()
	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_ConcurrentRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	maxSize := 50
	maxWait := 100 * time.Millisecond

	b := NewBatcher[int](maxSize, maxWait, 100)
	b.Start(ctx)
	batcher := b

	// Concurrently schedule retries from multiple goroutines
	numGoroutines := 5
	itemsPerGoroutine := 10
	done := make(chan struct{})

	for g := range numGoroutines {
		go func(offset int) {
			items := make([]int, itemsPerGoroutine)
			for i := range itemsPerGoroutine {
				items[i] = offset*itemsPerGoroutine + i
			}
			_ = batcher.Retry(50*time.Millisecond, items...)
			done <- struct{}{}
		}(g)
	}

	// Wait for all goroutines to finish
	for range numGoroutines {
		<-done
	}

	// Wait for retries to be processed:
	// - retry ticker fires every 2*maxWait = 200ms
	// - items move to buffer, then size-based flush (50 items = maxSize) or timer-based flush
	// - need to wait for: retry delay (50ms) + retry tick (200ms) + potential timer flush (100ms)
	time.Sleep(400 * time.Millisecond)

	// Cancel and close - all items should already be flushed
	cancel()
	err := batcher.Close()
	require.NoError(t, err)

	// Collect all received items
	totalReceived := 0
	for batch := range batcher.OutChannel() {
		require.NoError(t, batch.Error)
		totalReceived += len(batch.Items)
	}

	expectedTotal := numGoroutines * itemsPerGoroutine
	require.Equal(t, expectedTotal, totalReceived, "should receive all retried items across all batches")
}
