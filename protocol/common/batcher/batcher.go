package batcher

import (
	"context"
	"sync"
	"time"
)

// Batcher accumulates items and flushes them in batches based on size or time thresholds.
// It maintains insertion order (FIFO) within batches and is thread-safe.
// This implementation follows Go's CSP approach using channels for communication.
type Batcher[T any] struct {
	maxSize int
	maxWait time.Duration

	addCh chan []T
	outCh chan BatchResult[T]

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

// NewBatcher creates a new Batcher instance.
// The batcher will automatically flush when ctx is canceled.
// maxSize: maximum number of items before triggering a flush
// maxWait: maximum duration to wait before flushing incomplete batch
// outChannelSize: size of the output channel buffer (0 for unbuffered, consider your use case
// providing it the right buffer if needed).
func NewBatcher[T any](ctx context.Context, maxSize int, maxWait time.Duration, outChannelSize int) *Batcher[T] {
	b := &Batcher[T]{
		maxSize: maxSize,
		maxWait: maxWait,
		outCh:   make(chan BatchResult[T], outChannelSize),
		addCh:   make(chan []T),
		ctx:     ctx,
	}

	b.wg.Add(1)
	go b.run()

	return b
}

func (b *Batcher[T]) OutChannel() <-chan BatchResult[T] {
	return b.outCh
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

// run is the background goroutine that handles time-based flushing.
func (b *Batcher[T]) run() {
	defer b.wg.Done()
	defer close(b.outCh) // Signal completion by closing output channel

	var buffer []T

	timer := time.NewTimer(b.maxWait)
	timer.Stop() // Stop initially since buffer is empty

	for {
		select {
		case <-b.ctx.Done():
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
		case <-timer.C:
			b.flush(&buffer, timer)
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

	select {
	case b.outCh <- batch:
		// Successfully sent
	case <-b.ctx.Done():
		// Context canceled during send, drop batch
		return
	}

	// Reset buffer for next batch
	*buffer = make([]T, 0, b.maxSize)
}

// Close waits for the background goroutine to finish and closes internal channels.
// The caller should cancel the context before calling Close() to trigger final flush.
func (b *Batcher[T]) Close() error {
	b.wg.Wait()
	return nil
}
