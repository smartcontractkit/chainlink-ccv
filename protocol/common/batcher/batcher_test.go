package batcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBatcher_SizeBasedFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 5
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Add exactly maxSize items
	for i := range maxSize {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Should receive a batch immediately
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, maxSize)
		// Verify order is preserved
		for i := range maxSize {
			require.Equal(t, i, batch.Items[i])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed immediately on reaching maxSize")
	}

	// Cancel context then close batcher
	cancel()
	err := batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_TimeBasedFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 100
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Add just 3 items (well below maxSize)
	for i := range 3 {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Should receive a batch after maxWait expires
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 3)
		// Verify order is preserved
		for i := range 3 {
			require.Equal(t, i, batch.Items[i])
		}
	case <-time.After(maxWait + 50*time.Millisecond):
		t.Fatal("expected batch to be flushed after maxWait timeout")
	}

	// Cancel context then close batcher
	cancel()
	err := batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_GracefulClose(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 100
	maxWait := 10 * time.Second

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Add some items (not enough to trigger size-based flush)
	for i := range 7 {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Cancel context to trigger flush
	cancel()

	// Give goroutine a moment to flush
	time.Sleep(10 * time.Millisecond)

	// Should receive the remaining batch
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 7)
		// Verify order is preserved
		for i := range 7 {
			require.Equal(t, i, batch.Items[i])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed after context cancellation")
	}

	// Now wait for goroutine to finish
	err := batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_InsertionOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Add items in specific order
	expectedOrder := []int{5, 3, 9, 1, 7, 2, 8, 4, 6, 0}
	for _, val := range expectedOrder {
		err := batcher.Add(val)
		require.NoError(t, err)
	}

	// Receive batch and verify order
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Equal(t, expectedOrder, batch.Items)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed")
	}

	// Cancel context then close batcher
	cancel()
	err := batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_MultipleBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 3
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Add items that will trigger multiple batches
	totalItems := 9
	for i := range totalItems {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Should receive 3 full batches
	for batchNum := range 3 {
		select {
		case batch := <-batcher.OutChannel():
			require.NoError(t, batch.Error)
			require.Len(t, batch.Items, maxSize)
			// Verify order within batch
			for i := range maxSize {
				expectedVal := batchNum*maxSize + i
				require.Equal(t, expectedVal, batch.Items[i])
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("expected batch %d to be flushed", batchNum)
		}
	}

	cancel()
	err := batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_EmptyClose(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Cancel context first
	cancel()

	// Should not receive any batch (empty batcher doesn't flush)
	select {
	case batch, ok := <-batcher.OutChannel():
		if ok {
			t.Fatalf("expected no batch when closing empty batcher, got batch with %d items", len(batch.Items))
		}
		// Channel closed without sending batch - correct
	case <-time.After(50 * time.Millisecond):
		// Timeout is also acceptable - no batch sent
	}

	// Now wait for goroutine to finish
	err := batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_ConcurrentAdds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	maxSize := 50
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 100)

	// Concurrently add items from multiple goroutines
	numGoroutines := 10
	itemsPerGoroutine := 20
	done := make(chan struct{})

	for range numGoroutines {
		go func() {
			for i := range itemsPerGoroutine {
				_ = batcher.Add(i)
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines to finish
	for range numGoroutines {
		<-done
	}

	// Cancel context to flush remaining items, then wait for goroutine
	cancel()
	_ = batcher.Close()

	totalReceived := countBatchItems(batcher.OutChannel(), 500*time.Millisecond)
	expectedTotal := numGoroutines * itemsPerGoroutine
	require.Equal(t, expectedTotal, totalReceived, "should receive all items across all batches")
}

func TestBatcher_ChannelBufferAdequate(t *testing.T) {
	// Test that when channel buffer is large enough, all items are delivered
	// including both main buffer and retry buffer items on shutdown
	ctx, cancel := context.WithCancel(t.Context())

	// Large enough buffer to hold all batches
	maxSize := 5
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 20)

	// Add items to main buffer (not enough to trigger size-based flush)
	mainItems := []int{1, 2, 3}
	for _, item := range mainItems {
		err := batcher.Add(item)
		require.NoError(t, err)
	}

	// Add items to retry buffer with long delay
	retryItems := []int{4, 5, 6, 7}
	err := batcher.Retry(5*time.Second, retryItems...)
	require.NoError(t, err)

	// Give time for items to be queued
	time.Sleep(50 * time.Millisecond)

	// Cancel context - should flush both main buffer and retry buffer
	cancel()
	err = batcher.Close()
	require.NoError(t, err)

	// Collect all batches
	allItems := collectBatches(batcher.OutChannel(), 500*time.Millisecond)

	// Should have received all items (main + retry)
	expectedTotal := len(mainItems) + len(retryItems)
	require.Len(t, allItems, expectedTotal, "should receive all items from both buffers")

	// Verify all items are present (order may vary due to batching)
	expectedItems := append(mainItems, retryItems...)
	for _, expected := range expectedItems {
		require.Contains(t, allItems, expected, "item %d should be present", expected)
	}
}

func TestBatcher_BlockingOnFullChannel(t *testing.T) {
	// Test that when channel buffer is small, flush blocks until consumer reads
	// This validates guaranteed delivery even with small buffers
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Small buffer - only 1 batch can be queued
	maxSize := 5
	maxWait := 10 * time.Millisecond

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 1)

	// Start consuming batches in background BEFORE adding items
	// This simulates a consumer that's ready to receive
	done := make(chan struct{})
	var allItems []int
	var mu sync.Mutex
	go func() {
		defer close(done)
		for batch := range batcher.OutChannel() {
			mu.Lock()
			allItems = append(allItems, batch.Items...)
			mu.Unlock()
			// Simulate slow consumer
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Add items that will trigger multiple flushes
	// With maxSize=5, this will create 6 batches
	totalItemsAdded := 0
	for i := range 30 {
		err := batcher.Add(i)
		require.NoError(t, err)
		totalItemsAdded++
	}

	// Cancel and close
	cancel()
	err := batcher.Close()
	require.NoError(t, err)

	// Wait for consumer to finish
	<-done

	// With blocking behavior, ALL items should be delivered
	mu.Lock()
	receivedCount := len(allItems)
	mu.Unlock()

	t.Logf("Added %d items, received %d items", totalItemsAdded, receivedCount)

	// Assert that ALL items were delivered (no drops)
	require.Equal(t, totalItemsAdded, receivedCount,
		"expected all items to be delivered with blocking send")
}

func TestBatcher_ContextCancelFlushGuarantee(t *testing.T) {
	// Regression test for the bug where context cancellation would drop buffered items
	// This test validates that all items are flushed even when context is canceled immediately
	ctx, cancel := context.WithCancel(t.Context())

	// Use large maxWait so auto-flush won't happen
	maxSize := 100
	maxWait := 10 * time.Second

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Add items that won't trigger size-based flush
	testItems := []int{1, 2, 3, 4, 5, 6, 7}
	for _, item := range testItems {
		err := batcher.Add(item)
		require.NoError(t, err)
	}

	// Cancel context immediately
	cancel()

	// Give goroutine a moment to process cancellation
	time.Sleep(10 * time.Millisecond)

	// Read from output channel - should receive all items
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, len(testItems), "all items should be flushed on context cancel")
		require.Equal(t, testItems, batch.Items, "items should match in order")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed after context cancellation - this is the BUG")
	}

	// Close and verify no more batches
	err := batcher.Close()
	require.NoError(t, err)

	// Channel should be closed now
	select {
	case batch, ok := <-batcher.OutChannel():
		if ok {
			t.Fatalf("expected channel to be closed, got batch with %d items", len(batch.Items))
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("expected channel to be closed")
	}
}

func TestBatcher_ChannelBufferMultipleBatchesWithRetry(t *testing.T) {
	// Test complex scenario with multiple batches and retry items
	ctx, cancel := context.WithCancel(t.Context())

	// Medium buffer that can hold several batches
	maxSize := 5
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher[int](ctx, maxSize, maxWait, 10)

	// Scenario 1: Add items that will trigger size-based flush
	for i := range 5 {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Wait for size-based flush
	time.Sleep(10 * time.Millisecond)

	// Scenario 2: Add items that will wait for timer
	for i := 10; i < 13; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Scenario 3: Add retry items with short delay
	err := batcher.Retry(20*time.Millisecond, 20, 21, 22)
	require.NoError(t, err)

	// Scenario 4: Add more retry items with longer delay
	err = batcher.Retry(5*time.Second, 30, 31)
	require.NoError(t, err)

	// Wait for timer-based flush and first retry to process
	time.Sleep(150 * time.Millisecond)

	// Add final items to main buffer
	err = batcher.Add(40, 41)
	require.NoError(t, err)

	// Cancel - should flush remaining items including long-delay retries
	cancel()
	err = batcher.Close()
	require.NoError(t, err)

	// Collect all batches
	allItems := collectBatches(batcher.OutChannel(), 500*time.Millisecond)

	// Verify we got all the items we added
	expectedItems := []int{
		0, 1, 2, 3, 4, // First batch (size-based)
		10, 11, 12, // Second batch (timer-based)
		20, 21, 22, // First retry batch
		30, 31, // Second retry batch (flushed on shutdown)
		40, 41, // Final items
	}

	require.Len(t, allItems, len(expectedItems), "should receive all items")

	// Verify all expected items are present
	for _, expected := range expectedItems {
		require.Contains(t, allItems, expected, "item %d should be present", expected)
	}
}

// collectBatches drains the output channel and returns all items from all batches.
func collectBatches(outCh <-chan BatchResult[int], timeout time.Duration) []int {
	var allItems []int
	timeoutCh := time.After(timeout)

	for {
		select {
		case batch, ok := <-outCh:
			if !ok {
				// Channel closed
				return allItems
			}
			allItems = append(allItems, batch.Items...)
		case <-timeoutCh:
			return allItems
		}
	}
}

// countBatchItems drains the output channel and counts total items received.
func countBatchItems(outCh <-chan BatchResult[int], timeout time.Duration) int {
	count := 0
	timeoutCh := time.After(timeout)

	for {
		select {
		case batch, ok := <-outCh:
			if !ok {
				// Channel closed
				return count
			}
			count += len(batch.Items)
		case <-timeoutCh:
			return count
		}
	}
}
