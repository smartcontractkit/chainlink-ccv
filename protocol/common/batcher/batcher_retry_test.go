package batcher

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBatcher_RetryBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 50 * time.Millisecond // Short maxWait so retry ticker runs every 100ms

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
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
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(itemsToRetry))
		require.Equal(t, itemsToRetry, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items to be flushed")
	}
}

func TestBatcher_RetryWithSizeBasedFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	outCh := make(chan BatchResult[int], 10)
	maxSize := 5
	maxWait := 50 * time.Millisecond // Short wait for retry ticker

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
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
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, maxSize)
		require.Equal(t, itemsToRetry, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items to trigger size-based flush")
	}
}

func TestBatcher_RetryMixedWithAdd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
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
	case batch := <-outCh:
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
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(retryItems))
		require.Equal(t, retryItems, batch.Items)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected retried items to be flushed")
	}
}

func TestBatcher_RetryMultipleBatchesWithDifferentDelays(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

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
	case batch := <-outCh:
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
	case batch := <-outCh:
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

	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Retry items in specific order
	retryItems := []int{5, 3, 9, 1, 7}
	retryDelay := 50 * time.Millisecond

	err := batcher.Retry(retryDelay, retryItems...)
	require.NoError(t, err)

	// Wait for retry to be processed (retry ticker is 2*maxWait = 200ms)
	time.Sleep(retryDelay + 2*maxWait + 100*time.Millisecond)

	// Should receive items in the same order they were retried
	select {
	case batch := <-outCh:
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

func TestBatcher_RetryWithContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Schedule items for retry with a long delay
	retryItems := []int{1, 2, 3}
	retryDelay := 5 * time.Second

	err := batcher.Retry(retryDelay, retryItems...)
	require.NoError(t, err)

	// Cancel context before retry delay expires
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Give goroutine time to process cancellation
	time.Sleep(50 * time.Millisecond)

	// On context cancellation, ALL items (including pending retries) should be flushed
	// to prevent data loss during shutdown
	select {
	case batch, ok := <-outCh:
		require.True(t, ok, "expected to receive a batch")
		require.Len(t, batch.Items, len(retryItems), "all retry items should be flushed on shutdown")
		require.Equal(t, retryItems, batch.Items)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected retry items to be flushed on context cancellation")
	}

	// Further retry calls should fail
	err = batcher.Retry(100*time.Millisecond, 99)
	require.Error(t, err)
	require.Equal(t, context.Canceled, err)

	// Close batcher
	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_RetryEmptySlice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Retry empty slice should not cause issues
	err := batcher.Retry(50 * time.Millisecond)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(200 * time.Millisecond)

	// Should not receive any batch
	select {
	case batch := <-outCh:
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

	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 50 * time.Millisecond // Short maxWait so retry ticker runs every 100ms

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Retry with zero delay - should be processed on next retry ticker
	retryItems := []int{1, 2, 3}

	err := batcher.Retry(0, retryItems...)
	require.NoError(t, err)

	// Wait for retry processing (retry ticker is 2*maxWait = 100ms)
	time.Sleep(2*maxWait + 100*time.Millisecond)

	// Should receive batch with retried items
	select {
	case batch := <-outCh:
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

	outCh := make(chan BatchResult[int], 100)
	maxSize := 50
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Concurrently schedule retries from multiple goroutines
	numGoroutines := 5
	itemsPerGoroutine := 10
	done := make(chan struct{})

	for g := 0; g < numGoroutines; g++ {
		go func(offset int) {
			items := make([]int, itemsPerGoroutine)
			for i := 0; i < itemsPerGoroutine; i++ {
				items[i] = offset*itemsPerGoroutine + i
			}
			_ = batcher.Retry(50*time.Millisecond, items...)
			done <- struct{}{}
		}(g)
	}

	// Wait for all goroutines to finish
	for g := 0; g < numGoroutines; g++ {
		<-done
	}

	// Wait for retries to be processed (retry ticker is 2*maxWait = 200ms)
	time.Sleep(150*time.Millisecond + 2*maxWait)

	// Cancel to flush any remaining items
	cancel()

	// Close batcher and wait for completion
	err := batcher.Close()
	require.NoError(t, err)

	// Collect all received items
	totalReceived := 0
	for batch := range outCh {
		require.NoError(t, batch.Error)
		totalReceived += len(batch.Items)
	}

	expectedTotal := numGoroutines * itemsPerGoroutine
	require.Equal(t, expectedTotal, totalReceived, "should receive all retried items across all batches")
}
