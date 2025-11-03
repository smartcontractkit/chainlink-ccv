package executor

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor/internal/message_heap"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// BackoffDuration is the duration to backoff when there is an error reading from the ccv data reader.
const BackoffDuration = 5 * time.Second

type Coordinator struct {
	executor            Executor
	messageSubscriber   MessageSubscriber
	leaderElector       LeaderElector
	lggr                logger.Logger
	monitoring          Monitoring
	ccvDataCh           chan MessageWithCCVData
	executableMessageCh chan MessageWithCCVData
	doneCh              chan struct{}
	cancel              context.CancelFunc
	delayedMessageHeap  *message_heap.MessageHeap
	mu                  sync.RWMutex
	running             bool
}

type Option func(*Coordinator)

func WithLogger(lggr logger.Logger) Option {
	return func(ec *Coordinator) {
		ec.lggr = lggr
	}
}

func WithExecutor(executor Executor) Option {
	return func(ec *Coordinator) {
		ec.executor = executor
	}
}

func WithMessageSubscriber(sub MessageSubscriber) Option {
	return func(ec *Coordinator) {
		ec.messageSubscriber = sub
	}
}

func WithMonitoring(monitoring Monitoring) Option {
	return func(ec *Coordinator) {
		ec.monitoring = monitoring
	}
}

func WithLeaderElector(leaderElector LeaderElector) Option {
	return func(ec *Coordinator) {
		ec.leaderElector = leaderElector
	}
}

func NewCoordinator(options ...Option) (*Coordinator, error) {
	ec := &Coordinator{
		ccvDataCh: make(chan MessageWithCCVData, 100),
		doneCh:    make(chan struct{}),
	}

	for _, opt := range options {
		opt(ec)
	}

	if err := ec.validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	return ec, nil
}

func (ec *Coordinator) Start(ctx context.Context) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if ec.running {
		return fmt.Errorf("coordinator already running")
	}

	ec.running = true
	ctx, cancel := context.WithCancel(ctx)
	ec.cancel = cancel
	ec.delayedMessageHeap = &message_heap.MessageHeap{}
	heap.Init(ec.delayedMessageHeap)

	go ec.run(ctx)

	ec.lggr.Infow("Coordinator started")

	return nil
}

func (ec *Coordinator) Close() error {
	ec.mu.RLock()
	if !ec.running {
		ec.mu.RUnlock()
		return fmt.Errorf("coordinator not running")
	}
	ec.mu.RUnlock()

	ec.lggr.Infow("Coordinator stopping")
	ec.cancel()
	<-ec.doneCh

	// Close all channels
	close(ec.ccvDataCh)
	if ec.executableMessageCh != nil {
		close(ec.executableMessageCh)
	}

	ec.mu.Lock()
	ec.running = false
	ec.mu.Unlock()

	ec.lggr.Infow("Coordinator stopped")

	return nil
}

func (ec *Coordinator) run(ctx context.Context) {
	defer close(ec.doneCh)
	defer func() {
		ec.lggr.Infow("Coordinator run loop exited")
		ec.mu.Lock()
		defer ec.mu.Unlock()
		ec.running = false
	}()

	var wg sync.WaitGroup
	streamerResults, err := ec.messageSubscriber.Start(ctx, &wg)
	if err != nil {
		ec.lggr.Errorw("failed to start ccv result streamer", "error", err)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			ec.lggr.Infow("Coordinator exiting")
			return
		case streamResult, ok := <-streamerResults:
			if !ok {
				ec.lggr.Warnw("streamerResults closed")
				// TODO: handle reconnection logic
				// TODO: support multiple sources
			}

			if streamResult.Error != nil {
				ec.lggr.Errorw("error reading from ccv result streamer", "error", streamResult.Error)
			}

			for _, msg := range streamResult.Messages {
				err := ec.executor.CheckValidMessage(ctx, msg)
				if err != nil {
					ec.lggr.Errorw("invalid message, skipping", "error", err, "message", msg)
					continue
				}

				id, _ := msg.MessageID()

				if ec.delayedMessageHeap.Has(id) {
					ec.lggr.Infow("message already in delayed heap, skipping", "messageID", id)
					continue
				}

				// get message delay from leader elector
				readyTimestamp := ec.leaderElector.GetReadyTimestamp(id, time.Now().Unix())

				heap.Push(ec.delayedMessageHeap, &message_heap.MessageWithTimestamp{
					Payload:   &msg,
					ReadyTime: readyTimestamp,
				})
			}
		case <-ticker.C:
			// todo: get this current time from a single source across all executors
			currentTime := time.Now().Unix()
			readyMessages := ec.delayedMessageHeap.PopAllReady(currentTime)
			for _, message := range readyMessages {
				go func() {
					message := message
					id, _ := message.MessageID() // can we make this less bad?
					ec.lggr.Infow("processing message with ID", "messageID", id)
					err := ec.executor.AttemptExecuteMessage(ctx, message)
					if errors.Is(err, ErrMsgAlreadyExecuted) {
						ec.lggr.Infow("message already executed, skipping", "messageID", id)
						return
					} else if errors.Is(err, ErrInsufficientVerifiers) {
						ec.lggr.Infow("not enough verifiers to execute message, will wait until next notification", "messageID", id, "error", err)
						return
					} else if err != nil {
						ec.lggr.Errorw("failed to process message", "messageID", id, "error", err)
						ec.monitoring.Metrics().IncrementMessagesProcessingFailed(ctx)
						return
					}
					ec.monitoring.Metrics().IncrementMessagesProcessed(ctx)
				}()
			}
		}
	}
}

// validate checks that all required components are configured.
func (ec *Coordinator) validate() error {
	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}

	appendIfNil(ec.executor, "executor")
	appendIfNil(ec.leaderElector, "leaderElector")
	appendIfNil(ec.lggr, "logger")
	appendIfNil(ec.messageSubscriber, "messageSubscriber")

	return errors.Join(errs...)
}

// Ready returns nil if the coordinator is ready, or an error otherwise.
func (ec *Coordinator) Ready() error {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	if !ec.running {
		return errors.New("coordinator not running")
	}

	return nil
}

// HealthReport returns a full health report of the coordinator and its dependencies.
func (ec *Coordinator) HealthReport() map[string]error {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	report := make(map[string]error)
	report[ec.Name()] = ec.Ready()

	return report
}

// Name returns the fully qualified name of the coordinator.
func (ec *Coordinator) Name() string {
	return "executor.Coordinator"
}
