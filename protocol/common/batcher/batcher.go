package batcher

import (
	"context"
	"sync"
	"time"
)

// Batcher accumulates items and flushes them in batches based on size or time thresholds.
// It maintains insertion order (FIFO) within batches and is thread-safe.
// The batcher also supports delayed retries of failed items via the Retry method.
type Batcher[T any] struct {
	maxSize int
	maxWait time.Duration
	outCh   chan<- BatchResult[T]

	mu          sync.Mutex
	timer       *time.Timer
	buffer      []T
	retryBuffer []retryItem[T]

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
// outCh: channel to send flushed batches to.
func NewBatcher[T any](ctx context.Context, maxSize int, maxWait time.Duration, outCh chan<- BatchResult[T]) *Batcher[T] {
	b := &Batcher[T]{
		maxSize: maxSize,
		maxWait: maxWait,
		outCh:   outCh,
		buffer:  make([]T, 0, maxSize),
		ctx:     ctx,
	}

	// Start the timer (will be reset on first Add)
	b.timer = time.NewTimer(maxWait)
	b.timer.Stop() // Stop immediately since buffer is empty

	b.wg.Add(1)
	go b.run()

	return b
}

// Add adds an item to the batcher. It may trigger a flush if the batch size is reached.
// This method is thread-safe and non-blocking.
func (b *Batcher[T]) Add(item ...T) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if context is canceled
	select {
	case <-b.ctx.Done():
		return b.ctx.Err()
	default:
	}

	// Reset timer if this is the first item
	if len(b.buffer) == 0 {
		b.timer.Reset(b.maxWait)
	}

	// Add item to buffer
	b.buffer = append(b.buffer, item...)

	// Flush if we've reached max size
	if len(b.buffer) >= b.maxSize {
		b.flushLocked()
	}

	return nil
}

// Retry schedules items to be retried after the specified delay.
// The items will be moved to the main buffer after the delay expires.
// This method is thread-safe and non-blocking. Keep in mind that minDelay is approximate,
// because the actual retry processing depends on the background goroutine's timing.
func (b *Batcher[T]) Retry(minDelay time.Duration, items ...T) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if context is canceled
	select {
	case <-b.ctx.Done():
		return b.ctx.Err()
	default:
	}

	retryTime := time.Now().Add(minDelay)
	for _, item := range items {
		b.retryBuffer = append(b.retryBuffer, retryItem[T]{
			item:      item,
			retryTime: retryTime,
		})
	}
	return nil
}

// run is the background goroutine that handles time-based flushing and retry processing.
func (b *Batcher[T]) run() {
	defer b.wg.Done()
	defer close(b.outCh) // Signal completion by closing output channel

	// Ticker to periodically check for retry items that are ready
	// Make it longer than maxWait to avoid excessive wake-ups
	retryTicker := time.NewTicker(b.maxWait * 2)
	defer retryTicker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			// Context canceled, flush remaining items and exit
			b.mu.Lock()
			b.flushLocked()
			b.mu.Unlock()
			return
		case <-b.timer.C:
			// Timer expired, flush current batch
			b.mu.Lock()
			b.flushLocked()
			b.mu.Unlock()
		case <-retryTicker.C:
			// Check for retry items that are ready
			b.mu.Lock()
			b.processRetryBufferLocked()
			b.mu.Unlock()
		}
	}
}

// processRetryBufferLocked moves items from retryBuffer to main buffer if their retry time has elapsed.
// Must be called with lock held.
func (b *Batcher[T]) processRetryBufferLocked() {
	if len(b.retryBuffer) == 0 {
		return
	}

	now := time.Now()
	remainingRetries := make([]retryItem[T], 0, len(b.retryBuffer))

	for _, retry := range b.retryBuffer {
		if now.After(retry.retryTime) || now.Equal(retry.retryTime) {
			// Retry time has elapsed, move to main buffer
			b.buffer = append(b.buffer, retry.item)

			// Reset timer if this is the first item in buffer
			if len(b.buffer) == 1 {
				b.timer.Reset(b.maxWait)
			}
		} else {
			// Not ready yet, keep in retry buffer
			remainingRetries = append(remainingRetries, retry)
		}
	}

	// Flush if we've reached max size
	if len(b.buffer) >= b.maxSize {
		b.flushLocked()
	}

	b.retryBuffer = remainingRetries
}

// flushLocked sends the current buffer as a batch. Must be called with lock held.
func (b *Batcher[T]) flushLocked() {
	if len(b.buffer) == 0 {
		return
	}

	// Stop the timer
	if !b.timer.Stop() {
		// Timer already fired, drain the channel
		select {
		case <-b.timer.C:
		default:
		}
	}

	// Create batch with current buffer
	batch := BatchResult[T]{
		Items: b.buffer,
		Error: nil,
	}

	// Send batch (non-blocking with context check)
	select {
	case b.outCh <- batch:
		// Successfully sent
	case <-b.ctx.Done():
		// Context canceled during send
		return
	}

	// Reset buffer for next batch
	b.buffer = make([]T, 0, b.maxSize)
}

// Close waits for the background goroutine to finish.
// The caller should cancel the context before calling Close() to trigger final flush.
func (b *Batcher[T]) Close() error {
	b.wg.Wait()
	return nil
}
