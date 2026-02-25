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

func TestBatcher_CloseWithPendingItems(t *testing.T) {
	maxSize := 100           // Large size to ensure items stay in buffer
	maxWait := 1 * time.Hour // Very long wait to ensure timer doesn't flush

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// Add items that won't trigger size-based flush
	for i := range 5 {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Close immediately - should flush pending items
	err = batcher.Close()
	require.NoError(t, err)

	// Should receive the pending items
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 5)
		for i := range 5 {
			require.Equal(t, i, batch.Items[i])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected pending items to be flushed on close")
	}

	// Channel should be closed after receiving all items
	_, ok := <-batcher.OutChannel()
	require.False(t, ok, "output channel should be closed")
}

func TestBatcher_CloseDuringFlush(t *testing.T) {
	maxSize := 5
	maxWait := 1 * time.Second

	// Use unbuffered channel to control flush timing
	batcher := NewBatcher[int](maxSize, maxWait, 0)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Go(func() {
		time.Sleep(50 * time.Millisecond) // Delay receiving to simulate slow consumer
		batch, ok := <-batcher.OutChannel()
		if ok {
			require.NoError(t, batch.Error)
			require.Len(t, batch.Items, maxSize)
		}
	})

	// Add items to trigger flush
	for i := range maxSize {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Try to close while flush might be in progress
	time.Sleep(10 * time.Millisecond)
	err = batcher.Close()
	require.NoError(t, err)

	wg.Wait()
}

func TestBatcher_MultipleCloses(t *testing.T) {
	maxSize := 10
	maxWait := 1 * time.Second

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// First close
	err = batcher.Close()
	require.NoError(t, err)

	// Second close - StateMachine will return an error, which is fine
	// The important part is it doesn't panic or cause other issues
	_ = batcher.Close()
}

func TestBatcher_ConcurrentAddAndClose(t *testing.T) {
	maxSize := 10
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 100)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 20

	// Start multiple goroutines adding items
	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 10 {
				_ = batcher.Add(id*100 + j) // Ignore errors after close
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	// Close while adds are happening
	time.Sleep(20 * time.Millisecond)
	err = batcher.Close()
	require.NoError(t, err)

	// Wait for all add goroutines to complete
	wg.Wait()

	// Should be able to drain the channel without panic
	drained := 0
	for range batcher.OutChannel() {
		drained++
	}
}

func TestBatcher_RapidStartStop(t *testing.T) {
	// Test rapid start/stop cycles to ensure no resource leaks
	for i := range 10 {
		batcher := NewBatcher[int](10, 1*time.Second, 10)
		err := batcher.Start(context.Background())
		require.NoError(t, err)

		// Optionally add some items
		if i%2 == 0 {
			_ = batcher.Add(i)
		}

		err = batcher.Close()
		require.NoError(t, err)
	}
}

func TestBatcher_AddMultipleItemsAtOnce(t *testing.T) {
	maxSize := 10
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, batcher.Close())
	}()

	// Add multiple items in one call
	err = batcher.Add(1, 2, 3, 4, 5)
	require.NoError(t, err)

	// Add more to reach maxSize
	err = batcher.Add(6, 7, 8, 9, 10)
	require.NoError(t, err)

	// Should receive a batch
	select {
	case batch := <-batcher.OutChannel():
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, maxSize)
		// Verify order
		for i := range maxSize {
			require.Equal(t, i+1, batch.Items[i])
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected batch to be flushed")
	}
}

func TestBatcher_NoDataRaceOnBuffer(t *testing.T) {
	// This test is specifically designed to be run with -race flag
	maxSize := 20
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 100)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	var wg sync.WaitGroup
	numWriters := 10
	numReaders := 2

	// Multiple writers
	for i := range numWriters {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 50 {
				_ = batcher.Add(id*1000 + j)
			}
		}(i)
	}

	// Multiple readers
	for range numReaders {
		wg.Go(func() {
			for {
				select {
				case batch, ok := <-batcher.OutChannel():
					if !ok {
						return
					}
					// Just consume the batch
					_ = batch
				case <-time.After(500 * time.Millisecond):
					return
				}
			}
		})
	}

	wg.Wait()
	err = batcher.Close()
	require.NoError(t, err)
}

func TestBatcher_FlushDoesNotPanicOnContextDone(t *testing.T) {
	maxSize := 5
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 0) // Unbuffered
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// Add items
	for i := range 3 {
		err := batcher.Add(i)
		require.NoError(t, err)
	}

	// Close without consuming - flush will encounter closed stopCh during send
	err = batcher.Close()
	require.NoError(t, err)

	// Drain any received batches
	for range batcher.OutChannel() {
		// Just drain
	}
}

func TestBatcher_TimerResetOnFirstItem(t *testing.T) {
	maxSize := 100
	maxWait := 100 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, batcher.Close())
	}()

	start := time.Now()

	// Add first item - should start timer
	err = batcher.Add(1)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(30 * time.Millisecond)

	// Add second item - should NOT reset timer
	err = batcher.Add(2)
	require.NoError(t, err)

	// Should receive batch after original timer expires (not reset)
	select {
	case batch := <-batcher.OutChannel():
		elapsed := time.Since(start)
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 2)
		// Should flush around maxWait time, not maxWait + 30ms
		require.Less(t, elapsed, maxWait+50*time.Millisecond)
		require.Greater(t, elapsed, maxWait-10*time.Millisecond)
	case <-time.After(maxWait + 100*time.Millisecond):
		t.Fatal("expected batch to be flushed after maxWait")
	}
}

func TestBatcher_EmptyBatchNotSent(t *testing.T) {
	maxSize := 10
	maxWait := 50 * time.Millisecond

	batcher := NewBatcher[int](maxSize, maxWait, 10)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// Don't add anything, just wait for timer to potentially fire
	time.Sleep(maxWait + 50*time.Millisecond)

	// Close
	err = batcher.Close()
	require.NoError(t, err)

	// Should not receive any batch
	batches := 0
	for range batcher.OutChannel() {
		batches++
	}
	require.Equal(t, 0, batches, "empty batcher should not send any batches")
}

func TestBatcher_OutChannelBufferFull(t *testing.T) {
	maxSize := 5
	maxWait := 1 * time.Second
	bufferSize := 2

	batcher := NewBatcher[int](maxSize, maxWait, bufferSize)
	err := batcher.Start(context.Background())
	require.NoError(t, err)

	// Fill output buffer without reading
	for i := range bufferSize {
		for j := range maxSize {
			err := batcher.Add(i*10 + j)
			require.NoError(t, err)
		}
	}

	// Wait for batches to be sent to the buffer
	time.Sleep(50 * time.Millisecond)

	// Now start consuming batches while adding more
	var wg sync.WaitGroup
	wg.Add(1)

	receivedBatches := 0
	go func() {
		defer wg.Done()
		for batch := range batcher.OutChannel() {
			require.NoError(t, batch.Error)
			receivedBatches++
		}
	}()

	// Add one more batch - should work without blocking indefinitely
	for j := range maxSize {
		err := batcher.Add(100 + j)
		require.NoError(t, err)
	}

	// Close and wait for consumer
	err = batcher.Close()
	require.NoError(t, err)

	wg.Wait()

	// Should have received all 3 batches
	require.Equal(t, 3, receivedBatches, "should have received all batches")
}
