package batcher

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBatcher_SizeBasedFlush(t *testing.T) {
	ctx := context.Background()
	outCh := make(chan BatchResult[int], 10)
	maxSize := 5
	maxWait := 1 * time.Second

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
	defer batcher.Close()

	// Add exactly maxSize items
	for i := 0; i < maxSize; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Should receive a batch immediately
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, maxSize)
		// Verify order is preserved
		for i := 0; i < maxSize; i++ {
			require.Equal(t, i, batch.Items[i])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed immediately on reaching maxSize")
	}
}

func TestBatcher_TimeBasedFlush(t *testing.T) {
	ctx := context.Background()
	outCh := make(chan BatchResult[int], 10)
	maxSize := 100
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
	defer batcher.Close()

	// Add just 3 items (well below maxSize)
	for i := 0; i < 3; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Should receive a batch after maxWait expires
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 3)
		// Verify order is preserved
		for i := 0; i < 3; i++ {
			require.Equal(t, i, batch.Items[i])
		}
	case <-time.After(maxWait + 50*time.Millisecond):
		t.Fatal("expected batch to be flushed after maxWait timeout")
	}
}

func TestBatcher_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	outCh := make(chan BatchResult[int], 10)
	maxSize := 100
	maxWait := 10 * time.Second

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
	defer batcher.Close()

	// Add some items
	for i := 0; i < 5; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Cancel context
	cancel()

	// Should receive the remaining batch after cancellation
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 5)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed on context cancellation")
	}

	// Further adds should fail
	err := batcher.Add(999)
	require.Error(t, err)
	require.Equal(t, context.Canceled, err)
}

func TestBatcher_GracefulClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	outCh := make(chan BatchResult[int], 10)
	maxSize := 100
	maxWait := 10 * time.Second

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Add some items (not enough to trigger size-based flush)
	for i := 0; i < 7; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Cancel context to trigger flush, then wait for goroutine to finish
	cancel()
	err := batcher.Close()
	require.NoError(t, err)

	// Should receive the remaining batch
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 7)
		// Verify order is preserved
		for i := 0; i < 7; i++ {
			require.Equal(t, i, batch.Items[i])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed after context cancellation")
	}
}

func TestBatcher_InsertionOrder(t *testing.T) {
	ctx := context.Background()
	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
	defer batcher.Close()

	// Add items in specific order
	expectedOrder := []int{5, 3, 9, 1, 7, 2, 8, 4, 6, 0}
	for _, val := range expectedOrder {
		err := batcher.Add(val)
		require.NoError(t, err)
	}

	// Receive batch and verify order
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Equal(t, expectedOrder, batch.Items)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected batch to be flushed")
	}
}

func TestBatcher_MultipleBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outCh := make(chan BatchResult[int], 10)
	maxSize := 3
	maxWait := 1 * time.Second

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
	defer batcher.Close()

	// Add items that will trigger multiple batches
	totalItems := 10
	for i := 0; i < totalItems; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Should receive 3 full batches
	for batchNum := 0; batchNum < 3; batchNum++ {
		select {
		case batch := <-outCh:
			require.NoError(t, batch.Error)
			require.Len(t, batch.Items, maxSize)
			// Verify order within batch
			for i := 0; i < maxSize; i++ {
				expectedVal := batchNum*maxSize + i
				require.Equal(t, expectedVal, batch.Items[i])
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("expected batch %d to be flushed", batchNum)
		}
	}

	// Cancel context to flush the remaining 1 item, then wait for goroutine
	cancel()
	err := batcher.Close()
	require.NoError(t, err)

	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 1)
		require.Equal(t, 9, batch.Items[0])
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected remaining batch to be flushed after context cancellation")
	}
}

func TestBatcher_EmptyClose(t *testing.T) {
	ctx := context.Background()
	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Close without adding any items
	err := batcher.Close()
	require.NoError(t, err)

	// Should not receive any batch
	select {
	case <-outCh:
		t.Fatal("expected no batch when closing empty batcher")
	case <-time.After(50 * time.Millisecond):
		// Correct behavior - no batch sent
	}
}

func TestBatcher_ConcurrentAdds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	outCh := make(chan BatchResult[int], 100)
	maxSize := 50
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)
	defer batcher.Close()

	// Concurrently add items from multiple goroutines
	numGoroutines := 10
	itemsPerGoroutine := 20
	done := make(chan struct{})

	for g := 0; g < numGoroutines; g++ {
		go func() {
			for i := 0; i < itemsPerGoroutine; i++ {
				_ = batcher.Add(i)
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines to finish
	for g := 0; g < numGoroutines; g++ {
		<-done
	}

	// Cancel context to flush remaining items, then wait for goroutine
	cancel()
	_ = batcher.Close()

	totalReceived := 0
	timeout := time.After(500 * time.Millisecond)
	for {
		select {
		case batch := <-outCh:
			require.NoError(t, batch.Error)
			totalReceived += len(batch.Items)
		case <-timeout:
			// No more batches
			goto done
		}
	}

done:
	expectedTotal := numGoroutines * itemsPerGoroutine
	require.Equal(t, expectedTotal, totalReceived, "should receive all items across all batches")
}
