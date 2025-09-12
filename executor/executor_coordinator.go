package executor

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	th "github.com/smartcontractkit/chainlink-ccv/executor/internal/timestamp_heap"
	cdr "github.com/smartcontractkit/chainlink-ccv/executor/pkg/ccvdatareader"
	e "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	le "github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
)

type Coordinator struct {
	executor            e.Executor
	ccvDataReader       cdr.CcvDataReader
	leaderElector       le.LeaderElector
	lggr                logger.Logger
	ccvDataCh           chan types.MessageWithCCVData
	executableMessageCh chan types.MessageWithCCVData //nolint:unused //will be used by executor
	doneCh              chan struct{}
	cancel              context.CancelFunc
	running             bool
	delayedMessageHeap  *th.MessageHeap
	mu                  sync.RWMutex
}

type Option func(*Coordinator)

func WithLogger(lggr logger.Logger) Option {
	return func(ec *Coordinator) {
		ec.lggr = lggr
	}
}

func WithExecutor(executor e.Executor) Option {
	return func(ec *Coordinator) {
		ec.executor = executor
	}
}

func WithCCVDataReader(ccvDataReader cdr.CcvDataReader) Option {
	return func(ec *Coordinator) {
		ec.ccvDataReader = ccvDataReader
	}
}

func WithLeaderElector(leaderElector le.LeaderElector) Option {
	return func(ec *Coordinator) {
		ec.leaderElector = leaderElector
	}
}

func NewCoordinator(options ...Option) (*Coordinator, error) {
	ec := &Coordinator{
		ccvDataCh: make(chan types.MessageWithCCVData, 100),
		doneCh:    make(chan struct{}),
	}

	for _, opt := range options {
		opt(ec)
	}

	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}
	appendIfNil(ec.executor, "executor")
	appendIfNil(ec.leaderElector, "leaderElector")
	appendIfNil(ec.lggr, "logger")
	appendIfNil(ec.ccvDataReader, "ccvDataReader")
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return ec, nil
}

func (ec *Coordinator) Start(ctx context.Context) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if ec.running {
		return fmt.Errorf("Coordinator already running")
	}

	ec.running = true
	ctx, cancel := context.WithCancel(ctx)
	ec.cancel = cancel
	ec.delayedMessageHeap = &th.MessageHeap{}
	heap.Init(ec.delayedMessageHeap)

	go ec.run(ctx)

	ec.lggr.Infow("Coordinator started")

	return nil
}

func (ec *Coordinator) Stop() error {
	ec.mu.RLock()
	if !ec.running {
		ec.mu.RUnlock()
		return fmt.Errorf("Coordinator not started")
	}
	ec.mu.RUnlock()

	ec.lggr.Infow("Coordinator stopping")
	ec.cancel()
	<-ec.doneCh
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

	messagesCh, err := ec.ccvDataReader.SubscribeMessages()
	if err != nil {
		ec.lggr.Errorw("failed to get messages from ccvDataReader", "error", err)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			ec.lggr.Infow("Coordinator exiting")
			return
		case msg, ok := <-messagesCh:
			if !ok {
				ec.lggr.Warnw("messagesCh closed")
				// TODO: handle reconnection logic
				// TODO: support multiple sources
			}

			err = ec.executor.CheckValidMessage(ctx, msg)
			if err != nil {
				ec.lggr.Errorw("invalid message, skipping", "error", err, "message", msg)
				continue
			}

			id, _ := msg.Message.MessageID()

			// get message delay from leader elector
			readyTimestamp := ec.leaderElector.GetReadyTimestamp(id, msg.Message, msg.VerifiedTimestamp)
			ec.lggr.Infow("waiting before processing message", "readyTimestamp", readyTimestamp, "messageID", id)

			heap.Push(ec.delayedMessageHeap, &th.MessageWithTimestamp{
				Payload:   &msg,
				ReadyTime: readyTimestamp,
			})
		case <-ticker.C:
			// todo: get this current time from a single source across all executors
			currentTime := time.Now().Unix()
			readyMessages := ec.delayedMessageHeap.PopAllReady(currentTime)
			for _, message := range readyMessages {
				go func() {
					message := message
					id, _ := message.Message.MessageID() // can we make this less bad?
					ec.lggr.Infow("processing message with ID", "messageID", id)
					err = ec.executor.ExecuteMessage(ctx, message)
					if err != nil {
						ec.lggr.Errorw("failed to process message", "messageID", id, "error", err)
					}
				}()
			}
		}
	}
}

// IsRunning returns whether the coordinator is running.
func (ec *Coordinator) IsRunning() bool {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.running
}
