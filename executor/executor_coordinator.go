package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	cdr "github.com/smartcontractkit/chainlink-ccv/executor/pkg/ccvdatareader"
	e "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	le "github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
)

type Coordinator struct {
	ccvDataCh           chan types.MessageWithCCVData
	executableMessageCh chan types.MessageWithCCVData //nolint:unused //will be used by executor

	doneCh chan struct{}

	executor      e.Executor
	ccvDataReader cdr.CcvDataReader
	leaderElector le.LeaderElector

	lggr    logger.Logger
	running bool
	cancel  context.CancelFunc
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

func NewExecutorCoordinator(options ...Option) (*Coordinator, error) {
	ec := &Coordinator{
		ccvDataCh: make(chan types.MessageWithCCVData, 100),
		doneCh:    make(chan struct{}),
	}

	for _, opt := range options {
		opt(ec)
	}

	var errs []error
	appendIfNil := func(field interface{}, fieldName string) {
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

	for {
		select {
		case <-ctx.Done():
			ec.lggr.Infow("Coordinator exiting")
			return
		case msg, ok := <-messagesCh:
			if !ok {
				ec.lggr.Warnw("messagesCh closed")
				// TODO: handle reconnection logic
			}
			ec.ccvDataCh <- msg
		case ccvData := <-ec.ccvDataCh:
			err := ec.ProcessMessage(ctx)
			if err != nil {
				ec.lggr.Errorw("failed to process indexer payload", "error", err)
			} else {
				ec.lggr.Infow("successfully processed indexer payload", "data", ccvData)
			}
		}
	}
}

func (ec *Coordinator) ProcessMessage(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			ec.lggr.Infow("executor main loop context done, exiting")
			return nil
		case msg, ok := <-ec.ccvDataCh:
			if !ok {
				ec.lggr.Warnw("ccvDataCh closed, exiting processMessage")
				return nil
			}

			// todo: perform some validations on the message
			id, err := msg.Message.MessageID()
			if err != nil {
				ec.lggr.Errorw("invalid message, failed to generate ID", "error", err, "message", msg)
				continue
			}

			err = ec.executor.CheckValidMessage(ctx, msg)
			if err != nil {
				ec.lggr.Errorw("invalid message, skipping", "error", err, "message", msg)
				continue
			}

			// get message delay from leader elector
			delay := ec.leaderElector.GetDelay(id, msg.Message.DestChainSelector, msg.ReadyTimestamp)
			if delay+msg.ReadyTimestamp > time.Now().Unix() {
				// TODO: CCIP-7104 - use a priority queue ordered by execution time adds them to ccvDataCh at the right time.
				ec.lggr.Infow("message not ready yet, requeuing", "message", msg, "delay", delay)
				go func() {
					time.Sleep(time.Duration(delay+msg.ReadyTimestamp-time.Now().Unix()) * time.Second)
					ec.ccvDataCh <- msg
				}()
				continue
			}
			// if message is executable, send to executor

			err = ec.executor.ExecuteMessage(ctx, msg)
			if err != nil {
				ec.lggr.Errorw("failed to execute message", "error", err, "message", msg)
			} else {
				ec.lggr.Infow("successfully executed message", "message", msg)
			}
		}
	}
}

// IsRunning returns whether the coordinator is running
func (ec *Coordinator) IsRunning() bool {
	return ec.running
}
