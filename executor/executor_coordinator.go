package executor

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	protocol_types "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"sync"
	"time"

	th "github.com/smartcontractkit/chainlink-ccv/executor/internal/timestamp_heap"
	e "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	le "github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
)

// BackoffDuration is the duration to backoff when there is an error reading from the ccv data reader.
const BackoffDuration = 5 * time.Second

type Coordinator struct {
	executor            e.Executor
	ccvDataReader       protocol_types.OffchainStorageReader
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

func WithCCVDataReader(ccvDataReader protocol_types.OffchainStorageReader) Option {
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

func startReading(
	ctx context.Context,
	lggr logger.Logger,
	wg *sync.WaitGroup,
	reader protocol_types.OffchainStorageReader,
) <-chan protocol_types.QueryResponse {
	messagesCh := make(chan protocol_types.QueryResponse)
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer close(messagesCh)

		for {
			select {
			case <-ctx.Done():
				// Context canceled, stop loop.
				return
			default:
				// Non-blocking: call ReadCCVData
				responses, err := reader.ReadCCVData(ctx)
				if err != nil {
					lggr.Errorw("failed to read ccv data", "error", err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(BackoffDuration):
					}
					continue
				}
				for _, msg := range responses {
					select {
					case <-ctx.Done():
						return
					case messagesCh <- msg:
					}
				}
			}
		}
	}()
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
	messagesCh := startReading(ctx, ec.lggr, &wg, ec.ccvDataReader)

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

			// convert query response to message with ccv data

			err := ec.executor.CheckValidMessage(ctx, msg)
			if err != nil {
				ec.lggr.Errorw("invalid message, skipping", "error", err, "message", msg)
				continue
			}

			id, _ := msg.Message.MessageID()

			// get message delay from leader elector
			readyTimestamp := ec.leaderElector.GetReadyTimestamp(id, msg.Message, msg.VerifiedTimestamp)
			ec.lggr.Infow("waiting before processing message", "readyTimestamp", readyTimestamp, "messageID", id)

			heap.Push(ec.delayedMessageHeap, &th.MessageWithTimestamp{
				Payload:   msg,
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
