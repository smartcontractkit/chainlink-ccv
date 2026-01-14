package worker

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
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
				go func(t *Task) {
					s.ready <- t
				}(task)
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
	shouldEnqueue, delay := s.shouldEnqueue(t)
	if !shouldEnqueue {
		s.dlq <- t
		lastErrStr := ""
		if t.lastErr != nil {
			lastErrStr = t.lastErr.Error()
		}

		if err := t.SetMessageStatus(ctx, common.MessageTimeout, lastErrStr); err != nil {
			return errors.New("unable to update message status to timeout. message is already in dlq")
		}

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
