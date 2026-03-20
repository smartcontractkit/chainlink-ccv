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

type Scheduler struct {
	lggr      logger.Logger
	config    config.SchedulerConfig
	stopCh    chan struct{}
	mu        sync.Mutex
	delayHeap *DelayHeap
	ready     chan *Task
	dlq       chan *Task
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

	return &Scheduler{
		lggr:      lggr,
		config:    config,
		mu:        sync.Mutex{},
		delayHeap: delayHeap,
		stopCh:    make(chan struct{}),
		ready:     make(chan *Task, 1),
		dlq:       make(chan *Task, 1),
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

	return true, s.backoff(t.attempt + 1)
}

func (s *Scheduler) backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 1
	}

	// Create an exponential: BaseDelay * 2^(attempt-1)
	d := s.config.BaseDelay << (attempt - 1)
	if s.config.MaxDelay > 0 && d > s.config.MaxDelay {
		// Only allow tasks to be delayed for up to the max configurable delay
		d = s.config.MaxDelay
	}

	// Invariant check to ensure only positive integers are returned
	// Shouldn't ever be triggered but to prevent downstream issues, we'll just assert on it.
	if d < 0 {
		s.lggr.Warn("Invariant Check triggered in Scheduler, messages will still be scheduled however no delay will be added.")
		d = s.config.BaseDelay
	}

	return time.Duration(d) * time.Millisecond
}

func (s *Scheduler) Ready() <-chan *Task {
	return s.ready
}

func (s *Scheduler) DLQ() <-chan *Task {
	return s.dlq
}

func (s *Scheduler) Enqueue(ctx context.Context, t *Task) error {
	if t == nil {
		return errors.New("cannot enqueue nil task")
	}
	shouldEnqueue, delay := s.shouldEnqueue(t)
	if !shouldEnqueue {
		s.dlq <- t
		return errors.New("unable to enqueue, max attempts reached. sending to dlq")
	}

	t.attempt++
	t.runAt = time.Now().Add(delay)

	// If there is no delay, the task is ready immediately and should be sent to the ready channel.
	if delay == 0 {
		select {
		case s.ready <- t:
			return nil
		case <-ctx.Done():
			return errors.New("unable to enqueue, context deadline exceeded")
		}
	}

	// Otherwise schedule for future execution on the delay heap
	s.mu.Lock()
	defer s.mu.Unlock()
	heap.Push(s.delayHeap, t)
	return nil
}
