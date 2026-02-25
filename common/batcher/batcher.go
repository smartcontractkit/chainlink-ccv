package batcher

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// Batcher accumulates items and flushes them in batches based on size or time thresholds.
// It maintains insertion order (FIFO) within batches and is thread-safe.
// This implementation follows Go's CSP approach using channels for communication.
type Batcher[T any] struct {
	services.StateMachine
	wg     sync.WaitGroup
	stopCh services.StopChan

	maxSize int
	maxWait time.Duration
	addCh   chan []T

	outCh chan BatchResult[T]
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
func NewBatcher[T any](maxSize int, maxWait time.Duration, outChannelSize int) *Batcher[T] {
	b := &Batcher[T]{
		maxSize: maxSize,
		maxWait: maxWait,
		outCh:   make(chan BatchResult[T], outChannelSize),
		addCh:   make(chan []T),
		stopCh:  make(chan struct{}),
	}

	return b
}

func (b *Batcher[T]) Start(_ context.Context) error {
	return b.StartOnce("Batcher", func() error {
		b.wg.Go(func() { b.run() })
		return nil
	})
}

// Close waits for the background goroutine to finish and closes internal channels.
// Any pending items in the buffer will be flushed before closing.
func (b *Batcher[T]) Close() error {
	return b.StopOnce("Batcher", func() error {
		close(b.stopCh)
		b.wg.Wait()
		// Safe to close outCh now that run() has exited
		// Note: addCh is never closed, it's only drained when stopCh is closed
		close(b.outCh)
		return nil
	})
}

func (b *Batcher[T]) OutChannel() <-chan BatchResult[T] {
	return b.outCh
}

// Add adds an item to the batcher. It may trigger a flush if the batch size is reached.
// This method is thread-safe and returns an error if the batcher is not running.
func (b *Batcher[T]) Add(item ...T) error {
	if err := b.Ready(); err != nil {
		return err
	}

	select {
	case b.addCh <- item:
		return nil
	case <-b.stopCh:
		return b.Ready()
	}
}

// run is the background goroutine that handles time-based flushing.
func (b *Batcher[T]) run() {
	ctx, cancel := b.stopCh.NewCtx()
	defer cancel()

	var buffer []T

	timer := time.NewTimer(b.maxWait)
	timer.Stop() // Stop initially since buffer is empty

	defer func() {
		// Ensure timer is stopped to prevent goroutine leak
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		// Flush any remaining items before exiting
		if len(buffer) > 0 {
			batch := BatchResult[T]{
				Items: buffer,
				Error: nil,
			}
			// Use non-blocking send since we're shutting down
			select {
			case b.outCh <- batch:
			default:
				// If outCh is full, we can't block during shutdown
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case items, ok := <-b.addCh:
			if !ok {
				// addCh closed, exit
				return
			}
			// Reset timer if this is the first item
			if len(buffer) == 0 {
				timer.Reset(b.maxWait)
			}

			buffer = append(buffer, items...)
			if len(buffer) >= b.maxSize {
				b.flush(ctx, &buffer, timer)
			}
		case <-timer.C:
			b.flush(ctx, &buffer, timer)
		}
	}
}

// flush sends the current buffer as a batch if it's not empty.
// It stops the timer and resets the buffer after flushing.
func (b *Batcher[T]) flush(ctx context.Context, buffer *[]T, timer *time.Timer) {
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

	// Send the batch with context awareness
	// If context is done while sending, we'll catch it and return
	// Otherwise, we wait until the batch can be sent
	select {
	case b.outCh <- batch:
		// Successfully sent, continue to reset buffer
	case <-ctx.Done():
		// Context canceled while trying to send
		// Don't reset buffer here - the defer will attempt to send it
		return
	}

	// Reset buffer for next batch
	*buffer = make([]T, 0, b.maxSize)
}
