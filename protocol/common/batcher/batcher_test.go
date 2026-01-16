package batcher

import (
	"context"
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

	// Wait for all goroutines to finish adding
	for range numGoroutines {
		<-done
	}

	// Wait for size-based flushes to complete (200 items / 50 maxSize = 4 flushes)
	// Give time for the batcher's run loop to process all pending adds
	time.Sleep(50 * time.Millisecond)

	// Now cancel and close
	cancel()
	_ = batcher.Close()

	totalReceived := countBatchItems(batcher.OutChannel(), 500*time.Millisecond)
	expectedTotal := numGoroutines * itemsPerGoroutine
	require.Equal(t, expectedTotal, totalReceived, "should receive all items across all batches")
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
