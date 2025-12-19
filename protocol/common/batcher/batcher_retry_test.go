package batcher

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBatcher_RetryBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	outCh := make(chan BatchResult[int], 10)
	maxSize := 3
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Add items that reach maxSize and flush immediately
	for i := 0; i < 3; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// First batch should be flushed immediately due to size
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 3)
		require.Equal(t, []int{0, 1, 2}, batch.Items)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected first batch to be flushed")
	}

	// Simulate a failure - retry items with a short delay
	retryItems := []int{10, 11}
	err := batcher.Retry(150*time.Millisecond, retryItems)
	require.NoError(t, err)

	// Wait for retry delay to pass plus processing time
	time.Sleep(400 * time.Millisecond)

	// Second batch should be the retried items (flushed by timer)
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 2)
		require.Equal(t, []int{10, 11}, batch.Items)
	case <-time.After(300 * time.Millisecond):
		t.Fatal("expected retry batch to be flushed")
	}

	// Cancel context and close batcher
	cancel()
	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_RetryWithContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	outCh := make(chan BatchResult[int], 10)
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Schedule a retry
	retryItems := []int{1, 2, 3}
	err := batcher.Retry(500*time.Millisecond, retryItems)
	require.NoError(t, err)

	// Cancel context before retry time
	cancel()

	// Wait for batcher to close
	time.Sleep(50 * time.Millisecond)

	// Further retries should fail
	err = batcher.Retry(100*time.Millisecond, []int{4, 5})
	require.Error(t, err)

	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_RetryTriggersFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	outCh := make(chan BatchResult[int], 10)
	maxSize := 5
	maxWait := 10 * time.Second // Long wait to ensure size-based flush

	batcher := NewBatcher(ctx, maxSize, maxWait, outCh)

	// Add 2 items
	for i := 0; i < 2; i++ {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Retry 3 items with short delay (total will be 5, which equals maxSize)
	retryItems := []int{10, 11, 12}
	err := batcher.Retry(100*time.Millisecond, retryItems)
	require.NoError(t, err)

	// Wait for retry delay
	time.Sleep(250 * time.Millisecond)

	// Should get a batch of size 5 due to size-based flush
	select {
	case batch := <-outCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 5)
		// First 2 items should be original, next 3 should be retried
		require.Equal(t, 0, batch.Items[0])
		require.Equal(t, 1, batch.Items[1])
		require.Equal(t, 10, batch.Items[2])
		require.Equal(t, 11, batch.Items[3])
		require.Equal(t, 12, batch.Items[4])
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected batch to be flushed when size is reached")
	}

	// Cancel context and close batcher
	cancel()
	err = batcher.Close()
	require.NoError(t, err)
}
