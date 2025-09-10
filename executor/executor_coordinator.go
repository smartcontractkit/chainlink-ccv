package executor

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/utils"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

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
	delayedMessageHeap  *utils.MessageHeap
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
	if ec.running {
		return fmt.Errorf("Coordinator already running")
	}

	ec.running = true
	ctx, cancel := context.WithCancel(ctx)
	ec.cancel = cancel
	ec.delayedMessageHeap = &utils.MessageHeap{}
	heap.Init(ec.delayedMessageHeap)

	go ec.run(ctx)

	ec.lggr.Infow("Coordinator started")

	return nil
}

func (ec *Coordinator) Stop() error {
	if !ec.running {
		return fmt.Errorf("Coordinator not started")
	}

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
			delay := ec.leaderElector.GetDelay(id, msg.Message.DestChainSelector, msg.VerifiedTimestamp)
			ec.lggr.Infow("waiting delay before processing message", "delay", delay, "messageID", id)

			ec.delayedMessageHeap.Push(&utils.MessageWithTimestamp{
				Payload:   msg,
				ReadyTime: delay + msg.VerifiedTimestamp,
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
	return ec.running
}
