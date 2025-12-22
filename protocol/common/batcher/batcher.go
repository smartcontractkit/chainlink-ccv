package batcher

import (
	"context"
	"sync"
	"time"
)

// Batcher accumulates items and flushes them in batches based on size or time thresholds.
// It maintains insertion order (FIFO) within batches and is thread-safe.
// The batcher also supports delayed retries of failed items via the Retry method.
// This implementation follows Go's CSP approach using channels for communication.
type Batcher[T any] struct {
	maxSize int
	maxWait time.Duration

	addCh   chan []T
	retryCh chan []retryItem[T]
	outCh   chan<- BatchResult[T]

	ctx context.Context
	wg  sync.WaitGroup
}

// BatchResult carries a batch of items with an optional error.
// This generic type is used to pass batches of data between processing phases.
//
// Error Semantics:
//   - Batch-level errors (Error != nil): Infrastructure/system failures that prevented
//     batch creation (e.g., RPC failures, network errors, parse errors).
//     When Error is set, Items may be nil or partial.
//   - Per-item errors: Individual item processing failures (e.g., validation errors)
//     should be handled separately via dedicated error channels, not via this Error field.
//
// Example:
//   - BatchResult{Items: nil, Error: "RPC timeout"} → Batch-level failure, retry entire operation
//   - BatchResult{Items: [item1, item2], Error: nil} → Success, but item1 might fail validation later
type BatchResult[T any] struct {
	// Items contains the batch of elements (may be nil if Error is set)
	Items []T
	// Error indicates a batch-level error during batch creation/fetching
	Error error
}

// retryItem holds an item to be retried along with the time it should be retried.
type retryItem[T any] struct {
	item      T
	retryTime time.Time
}

// NewBatcher creates a new Batcher instance.
// The batcher will automatically flush when ctx is canceled.
// maxSize: maximum number of items before triggering a flush
// maxWait: maximum duration to wait before flushing incomplete batch
// outCh: channel to send flushed batches to (user is responsible for reading from this channel and
// providing it the right buffer if needed).
func NewBatcher[T any](ctx context.Context, maxSize int, maxWait time.Duration, outCh chan<- BatchResult[T]) *Batcher[T] {
	b := &Batcher[T]{
		maxSize: maxSize,
		maxWait: maxWait,
		outCh:   outCh,
		addCh:   make(chan []T),
		retryCh: make(chan []retryItem[T]),
		ctx:     ctx,
	}

	b.wg.Add(1)
	go b.run()

	return b
}

// Add adds an item to the batcher. It may trigger a flush if the batch size is reached.
// This method is thread-safe and non-blocking.
func (b *Batcher[T]) Add(item ...T) error {
	select {
	case b.addCh <- item:
		return nil
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
}

// Retry schedules items to be retried after the specified delay.
// The items will be moved to the main buffer after the delay expires.
// This method is thread-safe and non-blocking. Keep in mind that minDelay is approximate,
// because the actual retry processing depends on the background goroutine's timing.
func (b *Batcher[T]) Retry(minDelay time.Duration, items ...T) error {
	retryTime := time.Now().Add(minDelay)
	retryItems := make([]retryItem[T], 0, len(items))
	for _, item := range items {
		retryItems = append(retryItems, retryItem[T]{
			item:      item,
			retryTime: retryTime,
		})
	}

	select {
	case b.retryCh <- retryItems:
		return nil
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
}

// run is the background goroutine that handles time-based flushing and retry processing.
func (b *Batcher[T]) run() {
	defer b.wg.Done()
	defer close(b.outCh) // Signal completion by closing output channel

	var buffer []T
	var retryBuffer []retryItem[T]

	timer := time.NewTimer(b.maxWait)
	timer.Stop() // Stop initially since buffer is empty

	// Ticker to periodically check for retry items that are ready
	// Use 2*maxWait to avoid excessive wake-ups and ensure items flush separately
	retryTicker := time.NewTicker(b.maxWait * 2)
	defer retryTicker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			// Context canceled, move all retry items to buffer (ignore retry times)
			// and flush everything before exit to prevent data loss
			for _, retry := range retryBuffer {
				buffer = append(buffer, retry.item)
			}
			b.flush(&buffer, timer)
			return
		case items := <-b.addCh:
			// Reset timer if this is the first item
			if len(buffer) == 0 {
				timer.Reset(b.maxWait)
			}

			buffer = append(buffer, items...)
			if len(buffer) >= b.maxSize {
				b.flush(&buffer, timer)
			}
		case retryItems := <-b.retryCh:
			retryBuffer = append(retryBuffer, retryItems...)
		case <-timer.C:
			b.flush(&buffer, timer)
		case <-retryTicker.C:
			b.processRetryBuffer(&buffer, &retryBuffer, timer)
		}
	}
}

// flush sends the current buffer as a batch if it's not empty.
// It stops the timer and resets the buffer after flushing.
func (b *Batcher[T]) flush(buffer *[]T, timer *time.Timer) {
	if len(*buffer) == 0 {
		return
	}

	// Stop the timer
	if !timer.Stop() {
		// Timer already fired, drain the channel
		select {
		case <-timer.C:
		default:
		}
	}

	// Create batch with current buffer
	batch := BatchResult[T]{
		Items: *buffer,
		Error: nil,
	}

	// Send batch - non-blocking send without context cancellation check
	// If channel is full, the batch is dropped (fire & forget pattern)
	// This prevents blocking and allows the batcher to continue processing
	select {
	case b.outCh <- batch:
		// Successfully sent
	default:
		// Channel full - drop the batch
		// Consumer should ensure channel has adequate buffer or process faster
	}

	// Reset buffer for next batch
	*buffer = make([]T, 0, b.maxSize)
}

// processRetryBuffer moves items from retryBuffer to main buffer if their retry time has elapsed.
// Returns true if a flush was triggered due to reaching max size.
func (b *Batcher[T]) processRetryBuffer(buffer *[]T, retryBuffer *[]retryItem[T], timer *time.Timer) {
	if len(*retryBuffer) == 0 {
		return
	}

	now := time.Now()
	remainingRetries := make([]retryItem[T], 0, len(*retryBuffer))

	for _, retry := range *retryBuffer {
		if now.After(retry.retryTime) || now.Equal(retry.retryTime) {
			// Retry time has elapsed, move to main buffer
			*buffer = append(*buffer, retry.item)

			// Reset timer if this is the first item in buffer
			if len(*buffer) == 1 {
				timer.Reset(b.maxWait)
			}
		} else {
			// Not ready yet, keep in retry buffer
			remainingRetries = append(remainingRetries, retry)
		}
	}

	// Flush if we've reached max size
	if len(*buffer) >= b.maxSize {
		b.flush(buffer, timer)
	}

	*retryBuffer = remainingRetries
}

// Close waits for the background goroutine to finish and closes internal channels.
// The caller should cancel the context before calling Close() to trigger final flush.
func (b *Batcher[T]) Close() error {
	b.wg.Wait()
	close(b.addCh)
	close(b.retryCh)
	return nil
}
