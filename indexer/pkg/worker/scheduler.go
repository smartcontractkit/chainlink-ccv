package worker

import (
	"container/heap"
	"context"
	"errors"
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
}

func NewScheduler(lggr logger.Logger, config config.SchedulerConfig) (*Scheduler, error) {
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

func (s *Scheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *Scheduler) Stop() {
	s.stopCh <- struct{}{}
}

func (s *Scheduler) run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.config.TickerInterval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
		case <-ctx.Done():
			s.lggr.Info("Scheduler Exiting")
			return
		case <-ticker.C:
			s.mu.Lock()
			tasks := s.delayHeap.PopAllReady()
			s.mu.Unlock()
			for _, task := range tasks {
				go func() {
					task := task
					s.ready <- task
				}()
			}
		}
	}
}

func (s *Scheduler) VerificationVisabilityWindow() time.Duration {
	return time.Duration(s.config.VerificationVisabilityWindow) * time.Second
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

	// Invairant check to ensure only positive integers are returned
	// Shouldn't ever be triggered but to prevent downstream issues, we'll just assert on it.
	if d < 0 {
		s.lggr.Warn("Invairant Check triggered in Scheduler, messages will still be scheduled however no delay will be added.")
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
	shouldEnqueue, delay := s.shouldEnqueue(t)
	if !shouldEnqueue {
		s.dlq <- t
		return errors.New("unable to enqueue, max attempts reached. sending to dlq")
	}

	t.attempt++
	t.runAt = time.Now().Add(delay)

	if delay == 0 {
		s.mu.Lock()
		defer s.mu.Unlock()
		heap.Push(s.delayHeap, t)
		return nil
	}

	select {
	case s.ready <- t:
	case <-ctx.Done():
		return errors.New("unable to enqueue, context deadline exceeded")
	}

	return nil
}
