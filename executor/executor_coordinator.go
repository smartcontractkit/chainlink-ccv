package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	cdr "github.com/smartcontractkit/chainlink-ccv/executor/pkg/ccvdatareader"
	e "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	le "github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
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
			ec.lggr.Infow("message received... sending for procesing")
			err = ec.ProcessMessage(ctx, ccvData)
			if err != nil {
				ec.lggr.Errorw("failed to process indexer payload", "error", err)
			}
		}
	}
}

func (ec *Coordinator) ProcessMessage(ctx context.Context, msg types.MessageWithCCVData) error {
	// todo: perform some validations on the message
	err := ec.executor.CheckValidMessage(ctx, msg)
	if err != nil {
		ec.lggr.Errorw("invalid message, skipping", "error", err, "message", msg)
		return err
	}

	id, _ := msg.Message.MessageID()

	// get message delay from leader elector
	delay := ec.leaderElector.GetDelay(id, msg.Message.DestChainSelector, msg.ReadyTimestamp)
	ec.lggr.Infow("using delay", "delay", delay, "messageID", id)

	if delay+msg.ReadyTimestamp > time.Now().Unix() {
		// TODO: CCIP-7104 - use a priority queue ordered by execution time adds them to ccvDataCh at the right time.
		ec.lggr.Infow("message not ready yet", "messageID", id, "delay", delay)
		go func() {
			time.Sleep(time.Duration(delay+msg.ReadyTimestamp-time.Now().Unix()) * time.Second)

			// if message is executable, send to executor
			ec.lggr.Infow("passed delay for message, requeuing the message", "messageID", id)
			ec.ccvDataCh <- msg
		}()
		return err
	}

	err = ec.executor.ExecuteMessage(ctx, msg)
	if err != nil {
		ec.lggr.Errorw("failed to execute message", "error", err, "messageID", id)
		return err
	} else {
		ec.lggr.Infow("successfully executed message", "messageID", id)
	}
	return nil
}

// IsRunning returns whether the coordinator is running.
func (ec *Coordinator) IsRunning() bool {
	return ec.running
}
