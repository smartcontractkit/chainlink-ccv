package batcher

import (
	"context"
	"sync"
	"time"
)

// Batcher accumulates items and flushes them in batches based on size or time thresholds.
// It maintains insertion order (FIFO) within batches and is thread-safe.
type Batcher[T any] struct {
	maxSize int
	maxWait time.Duration
	outCh   chan<- BatchResult[T]

	mu     sync.Mutex
	buffer []T
	timer  *time.Timer

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewBatcher creates a new Batcher instance.
// maxSize: maximum number of items before triggering a flush
// maxWait: maximum duration to wait before flushing incomplete batch
// outCh: channel to send flushed batches to
func NewBatcher[T any](ctx context.Context, maxSize int, maxWait time.Duration, outCh chan<- BatchResult[T]) *Batcher[T] {
	batcherCtx, cancel := context.WithCancel(ctx)
	b := &Batcher[T]{
		maxSize: maxSize,
		maxWait: maxWait,
		outCh:   outCh,
		buffer:  make([]T, 0, maxSize),
		ctx:     batcherCtx,
		cancel:  cancel,
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
func (b *Batcher[T]) Add(item T) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if context is cancelled
	select {
	case <-b.ctx.Done():
		return b.ctx.Err()
	default:
	}

	// Add item to buffer
	b.buffer = append(b.buffer, item)

	// Reset timer if this is the first item
	if len(b.buffer) == 1 {
		b.timer.Reset(b.maxWait)
	}

	// Flush if we've reached max size
	if len(b.buffer) >= b.maxSize {
		b.flushLocked()
	}

	return nil
}

// run is the background goroutine that handles time-based flushing
func (b *Batcher[T]) run() {
	defer b.wg.Done()

	for {
		select {
		case <-b.ctx.Done():
			// Context cancelled, flush remaining items and exit
			b.mu.Lock()
			b.flushLocked()
			b.mu.Unlock()
			return
		case <-b.timer.C:
			// Timer expired, flush current batch
			b.mu.Lock()
			b.flushLocked()
			b.mu.Unlock()
		}
	}
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
		// Context cancelled during send
		return
	}

	// Reset buffer for next batch
	b.buffer = make([]T, 0, b.maxSize)
}

// Close gracefully shuts down the batcher, flushing any remaining items.
// It waits for the background goroutine to finish.
func (b *Batcher[T]) Close() error {
	b.cancel()
	b.wg.Wait()
	return nil
}
