package worker

import (
	"container/heap"
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Scheduler struct {
	lggr      logger.Logger
	config    SchedulerConfig
	stopCh    chan struct{}
	mu        sync.Mutex
	delayHeap *DelayHeap
	ready     chan *Task
	dlq       chan *Task
}

type SchedulerConfig struct {
	TickerInterval time.Duration
	MaxAttempts    int
	BaseDelay      time.Duration
	MaxDelay       time.Duration
	ReadyQueueSize int
	DLQSize        int
	JitterFrac     float64
}

func NewScheduler(lggr logger.Logger, config SchedulerConfig) (*Scheduler, error) {
	delayHeap := &DelayHeap{}
	heap.Init(delayHeap)
	if err := config.validate(); err != nil {
		return nil, err
	}

	return &Scheduler{
		lggr:      lggr,
		config:    config,
		mu:        sync.Mutex{},
		delayHeap: delayHeap,
		stopCh:    make(chan struct{}),
		ready:     make(chan *Task, config.ReadyQueueSize),
		dlq:       make(chan *Task, config.DLQSize),
	}, nil
}

func (c *SchedulerConfig) validate() error {
	if c.TickerInterval < time.Millisecond*10 {
		return errors.New("ticker interval must be larger than 10 milliseconds, will cause excess resource consumption")
	}

	if c.BaseDelay >= c.MaxDelay {
		return errors.New("max delay must be greater than base delay")
	}

	if c.MaxAttempts <= 0 {
		return errors.New("max attempts must be a positive non-zero integer")
	}

	if c.JitterFrac <= 0 {
		return errors.New("jitter frac must be a positive non-zero float")
	}

	return nil
}

func (s *Scheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *Scheduler) Stop() {
	s.stopCh <- struct{}{}
}

func (s *Scheduler) run(ctx context.Context) {
	ticker := time.NewTicker(s.config.TickerInterval)
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

func (s *Scheduler) shouldEnqueue(t *Task) (bool, time.Duration) {
	if t.attempt+1 >= s.config.MaxAttempts {
		return false, 0
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

	// To prevent a flood of messages from overwhelming the verifiers we'll add
	// a small percentage of the delay time. This should help favor smaller but
	// more frquent batches to the verifiers.
	if s.config.JitterFrac > 0 && attempt > 0 {
		j := s.config.JitterFrac * float64(d)
		// #nosec G404 - only used for jitter, not secure rand generation
		delta := time.Duration(rand.Int64N(int64(2*j))) - time.Duration(j)
		d += delta
	}

	// Invairant check to ensure only positive integers are returned
	// Shouldn't ever be triggered but to prevent downstream issues, we'll just assert on it.
	if d < 0 {
		s.lggr.Warn("Invairant Check triggered in Scheduler, messages will still be scheduled however no delay will be added.")
		d = 0
	}

	return d
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
