package worker

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ErrSchedulerFull is returned by TrySchedule when the heap has reached MaxHeapSize.
var ErrSchedulerFull = errors.New("scheduler heap is full")

type Scheduler struct {
	lggr      logger.Logger
	config    config.SchedulerConfig
	stopCh    chan struct{}
	mu        sync.Mutex
	delayHeap *DelayHeap
	ready     chan *Task
	dlq       chan *Task
	// slots is a counting semaphore that bounds the heap size.
	// nil means unbounded (MaxHeapSize == 0).
	slots     chan struct{}
	wg        sync.WaitGroup
	startOnce sync.Once
	stopOnce  sync.Once
}

func NewScheduler(lggr logger.Logger, config config.SchedulerConfig) (*Scheduler, error) {
	// Require a non-nil logger to avoid scattered nil-checks and to make
	// the dependency explicit for production code.
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}

	delayHeap := &DelayHeap{}
	heap.Init(delayHeap)

	var slots chan struct{}
	if config.MaxHeapSize > 0 {
		slots = make(chan struct{}, config.MaxHeapSize)
	}

	return &Scheduler{
		lggr:      lggr,
		config:    config,
		mu:        sync.Mutex{},
		delayHeap: delayHeap,
		stopCh:    make(chan struct{}),
		ready:     make(chan *Task, 1),
		dlq:       make(chan *Task, 1),
		slots:     slots,
	}, nil
}

// Start begins the scheduler's main loop in a separate goroutine. The service may only be started once, subsequent calls to Start will be no-ops.
func (s *Scheduler) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		s.wg.Go(func() {
			s.run(ctx)
		})
	})
}

// Stop the scheduler's main loop and wait for it to exit. The service may only be stopped once, subsequent calls to Stop will be no-ops.
func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

func (s *Scheduler) run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.config.TickerInterval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			s.lggr.Info("Scheduler Exiting")
			return
		case <-ctx.Done():
			s.lggr.Info("Scheduler Exiting")
			return
		case <-ticker.C:
			s.mu.Lock()
			tasks := s.delayHeap.PopAllReady()
			s.mu.Unlock()
			for _, task := range tasks {
				// Release the heap slot before blocking on the ready channel so
				// that new tasks can be scheduled while we wait for a worker.
				if s.slots != nil {
					<-s.slots
				}
				select {
				case s.ready <- task:
				case <-s.stopCh:
					s.lggr.Info("Scheduler Exiting")
					return
				case <-ctx.Done():
					s.lggr.Info("Scheduler Exiting")
					return
				}
			}
		}
	}
}

func (s *Scheduler) VerificationVisibilityWindow() time.Duration {
	return time.Duration(s.config.VerificationVisibilityWindow) * time.Second
}

func (s *Scheduler) shouldEnqueue(t *Task) (bool, time.Duration) {
	// If the TTL has expired, we won't retry the message
	if t.ttl.Before(time.Now()) {
		return false, time.Duration(0)
	}

	return true, s.backoff(t)
}

func (s *Scheduler) backoff(t *Task) time.Duration {
	attempt := t.attempt + 1
	if attempt < 1 {
		attempt = 1
	}

	d := s.config.BaseDelay << (attempt - 1)
	if s.config.MaxDelay > 0 && d > s.config.MaxDelay {
		d = s.config.MaxDelay
	}

	if s.config.BaseDelay > 0 && d <= 0 {
		s.lggr.Warnf("Invariant Check triggered in Scheduler, backoff delay overflowed to non-positive %dms for message %s at attempt %d, falling back to MaxDelay %dms.", d, t.messageID, attempt, s.config.MaxDelay)
		d = s.config.MaxDelay
	}

	return time.Duration(d) * time.Millisecond
}

func (s *Scheduler) Ready() <-chan *Task {
	return s.ready
}

func (s *Scheduler) DLQ() <-chan *Task {
	return s.dlq
}

// Enqueue enqueues t for execution. If the heap is at capacity (MaxHeapSize > 0)
// it blocks until a slot becomes available or ctx is canceled.
func (s *Scheduler) Enqueue(ctx context.Context, t *Task) error {
	if t == nil {
		return errors.New("cannot enqueue nil task")
	}
	shouldEnqueue, delay := s.shouldEnqueue(t)
	if !shouldEnqueue {
		s.dlq <- t
		return errors.New("task TTL expired, sent to DLQ")
	}

	t.attempt++
	t.runAt = time.Now().Add(delay)

	if delay == 0 {
		select {
		case s.ready <- t:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("enqueue cancelled: %w", ctx.Err())
		}
	}

	if s.slots != nil {
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return fmt.Errorf("enqueue cancelled waiting for heap slot: %w", ctx.Err())
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	heap.Push(s.delayHeap, t)
	return nil
}

// TryEnqueue enqueues t for execution. If the heap is at capacity it returns
// ErrSchedulerFull immediately without blocking.
func (s *Scheduler) TryEnqueue(t *Task) error {
	if t == nil {
		return errors.New("cannot enqueue nil task")
	}
	shouldEnqueue, delay := s.shouldEnqueue(t)
	if !shouldEnqueue {
		s.dlq <- t
		return errors.New("task TTL expired, sent to DLQ")
	}

	t.attempt++
	t.runAt = time.Now().Add(delay)

	if delay == 0 {
		select {
		case s.ready <- t:
			return nil
		default:
			return ErrSchedulerFull
		}
	}

	if s.slots != nil {
		select {
		case s.slots <- struct{}{}:
		default:
			return ErrSchedulerFull
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	heap.Push(s.delayHeap, t)
	return nil
}
