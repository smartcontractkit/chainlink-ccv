package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/executor/internal/message_heap"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// BackoffDuration is the duration to backoff when there is an error reading from the ccv data reader.
const BackoffDuration = 5 * time.Second

type Coordinator struct {
	services.StateMachine
	wg                 sync.WaitGroup
	executor           Executor
	messageSubscriber  MessageSubscriber
	leaderElector      LeaderElector
	lggr               logger.Logger
	monitoring         Monitoring
	processingCh       chan message_heap.MessageWithTimestamps
	cancel             context.CancelFunc
	delayedMessageHeap message_heap.MessageHeap
	running            atomic.Bool
	expiryDuration     time.Duration
	timeProvider       common.TimeProvider
	workerCount        int
}

// NewCoordinator creates a new executor coordinator.
func NewCoordinator(
	lggr logger.Logger,
	executor Executor,
	messageSubscriber MessageSubscriber,
	leaderElector LeaderElector,
	monitoring Monitoring,
	expiryDuration time.Duration,
	timeProvider common.TimeProvider,
) (*Coordinator, error) {
	ec := &Coordinator{
		lggr:              lggr,
		executor:          executor,
		messageSubscriber: messageSubscriber,
		leaderElector:     leaderElector,
		monitoring:        monitoring,
		processingCh:      make(chan message_heap.MessageWithTimestamps, 100),
		// cancel and delayedMessageHeap are initialized in Start()
		// running, wg, and services.StateMachine default initialization is fine.
		expiryDuration: expiryDuration,
		timeProvider:   timeProvider,
		workerCount:    10,
	}

	if err := ec.validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	return ec, nil
}

func (ec *Coordinator) Start(ctx context.Context) error {
	return ec.StartOnce("executor.Coordinator", func() error {
		c, cancel := context.WithCancel(context.Background())
		ec.cancel = cancel
		ec.delayedMessageHeap = *message_heap.NewMessageHeap()

		ec.running.Store(true)
		ec.wg.Add(1)
		go func() {
			defer ec.wg.Done()
			ec.run(c)
		}()

		ec.lggr.Infow("Coordinator started")

		return nil
	})
}

func (ec *Coordinator) Close() error {
	return ec.StopOnce("executor.Coordinator", func() error {
		ec.lggr.Infow("Coordinator stopping")

		// cancel the .run() goroutine and wait for it to exit.
		ec.cancel()
		ec.wg.Wait()

		// Close all channels
		close(ec.processingCh)

		// Update running state to reflect in healthcheck and readiness.
		ec.running.Store(false)

		ec.lggr.Infow("Coordinator stopped")

		return nil
	})
}

func (ec *Coordinator) run(ctx context.Context) {
	for i := 0; i < ec.workerCount; i++ {
		ec.wg.Add(1)
		go func() {
			defer ec.wg.Done()
			ec.handleMessage(ctx)
		}()
	}

	streamerResults, err := ec.messageSubscriber.Start(ctx, nil)
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

			for _, msgWithMetadata := range streamResult.Messages {
				msg := msgWithMetadata.Message
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

				// get message delay from leader elector using indexer's ingestion timestamp
				readyTimestamp := ec.leaderElector.GetReadyTimestamp(
					id,
					msg.DestChainSelector,
					msgWithMetadata.Metadata.IngestionTimestamp)

				ec.lggr.Infow("pushing message to delayed heap",
					"messageID", id,
					"ingestionTimestamp", msgWithMetadata.Metadata.IngestionTimestamp,
					"readyTimestamp", readyTimestamp,
				)

				ec.delayedMessageHeap.Push(message_heap.MessageWithTimestamps{
					Message:       &msg,
					ReadyTime:     readyTimestamp,
					ExpiryTime:    readyTimestamp.Add(ec.expiryDuration),
					RetryInterval: ec.leaderElector.GetRetryDelay(msg.DestChainSelector),
					MessageID:     id,
				})
			}
		case <-ticker.C:
			currentTime := ec.timeProvider.GetTime()

			// Process all messages that are ready to be processed.
			readyMessages := ec.delayedMessageHeap.PopAllReady(currentTime)
			ec.lggr.Debugw("found messages ready for processing",
				"count", len(readyMessages),
				"currentTime", currentTime.String(),
				"readyMessages", readyMessages,
			)
			for _, payload := range readyMessages {
				select {
				case ec.processingCh <- payload:
				default:
					ec.lggr.Warnw("processing channel full, pushing message back to heap", "messageID", payload.MessageID)
					ec.delayedMessageHeap.Push(payload)
				}
			}
		}
	}
}

func (ec *Coordinator) handleMessage(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-ec.processingCh:
			if !ok {
				return
			}
			currentTime := ec.timeProvider.GetTime()
			if currentTime.After(payload.ExpiryTime) {
				ec.lggr.Infow("message has expired", "messageID", payload.MessageID)
				return
			}

			message, id := *payload.Message, payload.MessageID

			ec.lggr.Infow("processing message with ID", "messageID", id)
			messageStatus, err := ec.executor.GetMessageStatus(ctx, message)
			if err != nil {
				ec.lggr.Errorw("failed to check message status", "messageID", id, "error", err)
			}

			if messageStatus.ShouldRetry {
				// todo: add exponential backoff here
				retryTime := currentTime.Add(payload.RetryInterval)
				ec.lggr.Infow("message should be retried, putting back in heap", "messageID", id)
				ec.delayedMessageHeap.Push(message_heap.MessageWithTimestamps{
					Message:       &message,
					ReadyTime:     retryTime,
					ExpiryTime:    payload.ExpiryTime,
					RetryInterval: payload.RetryInterval,
					MessageID:     id,
				})
			}
			if messageStatus.ShouldExecute {
				ec.lggr.Infow("attempting to execute message", "messageID", id)
				err = ec.executor.AttemptExecuteMessage(ctx, message)
				if errors.Is(err, ErrInsufficientVerifiers) {
					ec.lggr.Infow("not enough verifiers to execute message, will wait until next notification", "messageID", id, "error", err)
					return
				} else if err != nil {
					ec.lggr.Errorw("failed to process message", "messageID", id, "error", err)
					ec.monitoring.Metrics().IncrementMessagesProcessingFailed(ctx)
					return
				}
				ec.monitoring.Metrics().IncrementMessagesProcessed(ctx)
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
	appendIfNil(ec.monitoring, "monitoring")

	return errors.Join(errs...)
}

// Ready returns nil if the coordinator is ready, or an error otherwise.
func (ec *Coordinator) Ready() error {
	if !ec.running.Load() {
		return errors.New("coordinator not running")
	}

	return nil
}

// HealthReport returns a full health report of the coordinator and its dependencies.
func (ec *Coordinator) HealthReport() map[string]error {
	report := make(map[string]error)
	report[ec.Name()] = ec.Ready()

	return report
}

// Name returns the fully qualified name of the coordinator.
func (ec *Coordinator) Name() string {
	return "executor.Coordinator"
}
