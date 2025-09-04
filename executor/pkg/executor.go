package pkg

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Executor interface {
	ExecuteMessage(ctx context.Context, messageWithCCVData MessageWithCCVData) error
}

type ExecutorCoordinator struct {
	ccvDataCh           chan MessageWithCCVData
	executableMessageCh chan MessageWithCCVData

	stopCh chan struct{}
	doneCh chan struct{}

	executor      Executor
	ccvDataReader CcvDataReader
	leaderElector LeaderElector

	lggr    logger.Logger
	running bool
}

type Option func(*ExecutorCoordinator)

func WithLogger(lggr logger.Logger) Option {
	return func(ec *ExecutorCoordinator) {
		ec.lggr = lggr
	}
}

func WithExecutor(executor Executor) Option {
	return func(ec *ExecutorCoordinator) {
		ec.executor = executor
	}
}

func WithCCVDataReader(ccvDataReader CcvDataReader) Option {
	return func(ec *ExecutorCoordinator) {
		ec.ccvDataReader = ccvDataReader
	}
}

func WithLeaderElector(leaderElector LeaderElector) Option {
	return func(ec *ExecutorCoordinator) {
		ec.leaderElector = leaderElector
	}
}

func (ec *ExecutorCoordinator) Validate() error {
	if ec.executor == nil {
		return fmt.Errorf("executor is required")
	}
	return nil
}

func NewExecutorCoordinator(options ...Option) (*ExecutorCoordinator, error) {
	ec := &ExecutorCoordinator{
		ccvDataCh: make(chan MessageWithCCVData, 100),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}

	for _, opt := range options {
		opt(ec)
	}

	// Validate required fields
	if err := ec.Validate(); err != nil {
		return nil, err
	}

	return ec, nil
}

func (ec *ExecutorCoordinator) Start(ctx context.Context) error {
	if ec.running {
		return fmt.Errorf("ExecutorCoordinator already running")
	}

	ec.running = true
	go ec.run(ctx)

	ec.lggr.Infow("ExecutorCoordinator started")

	return nil
}

func (ec *ExecutorCoordinator) Stop() error {
	if !ec.running {
		return fmt.Errorf("ExecutorCoordinator not started")
	}

	ec.running = false

	close(ec.stopCh)
	<-ec.doneCh

	ec.lggr.Infow("ExecutorCoordinator stopped")

	return nil
}

func (ec *ExecutorCoordinator) run(ctx context.Context) {
	defer close(ec.doneCh)

	messagesCh, err := ec.ccvDataReader.subscribeMessages()
	if err != nil {
		ec.lggr.Errorw("failed to get messages from ccvDataReader", "error", err)
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	for {
		select {
		case <-ec.stopCh:
			ec.lggr.Infow("ExecutorCoordinator stop signal received, exiting")
			cancel()
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

func (ec *ExecutorCoordinator) ProcessMessage(ctx context.Context) error {
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

			// get message delay from leader elector
			delay := ec.leaderElector.get_delay(msg.CCVData[0].MessageID, msg.Message.DestChainSelector, msg.ReadyTimestamp)
			if delay+msg.ReadyTimestamp > uint64(time.Now().Unix()) {
				// not ready yet, requeue. In a real system, consider using a priority queue keyed on "readiness time"
				ec.lggr.Infow("message not ready yet, requeuing", "message", msg, "delay", delay)
				go func() {
					time.Sleep(time.Duration((delay + msg.ReadyTimestamp - uint64(time.Now().Unix())) * uint64(time.Second)))
					ec.ccvDataCh <- msg
				}()
				continue
			}
			// if message is executable, send to executor

			err := ec.executor.ExecuteMessage(ctx, msg)
			if err != nil {
				ec.lggr.Errorw("failed to execute message", "error", err, "message", msg)
			} else {
				ec.lggr.Infow("successfully executed message", "message", msg)
			}
		}
	}
}
