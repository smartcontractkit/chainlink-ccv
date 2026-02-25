package batcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBatcher_SizeBasedFlush(t *testing.T) {
	maxSize := 5
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, batcher.Close())
	}()

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
}

func TestBatcher_TimeBasedFlush(t *testing.T) {
	maxSize := 100
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, batcher.Close())
	}()

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
}

func TestBatcher_InsertionOrder(t *testing.T) {
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, batcher.Close())
	}()

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
}

func TestBatcher_MultipleBatches(t *testing.T) {
	maxSize := 3
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, batcher.Close())
	}()

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
}

func TestBatcher_EmptyClose(t *testing.T) {
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// Close immediately without adding anything
	err = batcher.Close()
	require.NoError(t, err)

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
}

func TestBatcher_ConcurrentAdds(t *testing.T) {
	maxSize := 50
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 100)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// Concurrently add items from multiple goroutines
	numGoroutines := 10
	itemsPerGoroutine := 20
	var wg sync.WaitGroup

	for range numGoroutines {
		wg.Go(func() {
			for i := range itemsPerGoroutine {
				err := batcher.Add(i)
				// If batcher is stopped during add, it's ok to get an error
				if err != nil {
					return
				}
			}
		})
	}

	// Wait for all goroutines to finish adding
	wg.Wait()

	// Wait for size-based flushes to complete (200 items / 50 maxSize = 4 flushes)
	// Give time for the batcher's run loop to process all pending adds
	time.Sleep(50 * time.Millisecond)

	// Now close
	err = batcher.Close()
	require.NoError(t, err)

	totalReceived := countBatchItems(batcher.OutChannel(), 500*time.Millisecond)
	expectedTotal := numGoroutines * itemsPerGoroutine
	require.Equal(t, expectedTotal, totalReceived, "should receive all items across all batches")
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

func TestBatcher_AddAfterClose(t *testing.T) {
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// Close the batcher
	err = batcher.Close()
	require.NoError(t, err)

	// Try to add after close - should return an error
	err = batcher.Add(1)
	require.Error(t, err, "Add() should return an error after Close()")
}

func TestBatcher_AddBeforeStart(t *testing.T) {
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](maxSize, maxWait, 10)

	// Try to add before Start() - should return an error
	err := batcher.Add(1)
	require.Error(t, err, "Add() should return an error before Start()")

	// Now start and it should work
	err = batcher.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, batcher.Close())
	}()

	err = batcher.Add(1)
	require.NoError(t, err, "Add() should work after Start()")
}
