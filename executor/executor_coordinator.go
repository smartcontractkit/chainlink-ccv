package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/message_heap"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// Coordinator is the main executor coordinator that manages the timing of a message lifecycle.
// It is responsible for reading messages from a source, managing a decentralized delay mechanism,
// dispatching them to workers for execution, and retrying if necessary.
type Coordinator struct {
	services.StateMachine
	wg                 sync.WaitGroup
	executor           Executor
	messageSubscriber  MessageSubscriber
	leaderElector      LeaderElector
	lggr               logger.Logger
	monitoring         Monitoring
	workerPoolTasks    chan message_heap.MessageWithTimestamps
	cancel             context.CancelFunc
	delayedMessageHeap message_heap.MessageHeap
	inFlight           map[protocol.Bytes32]struct{}
	inFlightMu         sync.RWMutex
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
	workerCount int,
) (*Coordinator, error) {
	ec := &Coordinator{
		lggr:              lggr,
		executor:          executor,
		messageSubscriber: messageSubscriber,
		leaderElector:     leaderElector,
		monitoring:        monitoring,
		workerPoolTasks:   make(chan message_heap.MessageWithTimestamps),
		// cancel and delayedMessageHeap are initialized in Start()
		// running, wg, and services.StateMachine default initialization is fine.
		expiryDuration: expiryDuration,
		timeProvider:   timeProvider,
		workerCount:    workerCount,
	}

	if err := ec.validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	return ec, nil
}

func (ec *Coordinator) Start(ctx context.Context) error {
	return ec.StartOnce("executor.Coordinator", func() error {
		if err := ec.executor.Start(ctx); err != nil {
			ec.lggr.Errorf("unable to start executor coordinator due to error: %w", err)
			return err
		}

		c, cancel := context.WithCancel(context.Background())
		ec.cancel = cancel
		ec.delayedMessageHeap = *message_heap.NewMessageHeap()
		ec.inFlight = make(map[protocol.Bytes32]struct{})
		ec.running.Store(true)

		// Start storage stream goroutine
		ec.wg.Go(func() {
			ec.runStorageStream(c)
		})

		// Start processing loop goroutine
		ec.wg.Go(func() {
			ec.runProcessingLoop(c)
		})

		// Start worker goroutines
		ec.wg.Add(ec.workerCount)
		for i := 0; i < ec.workerCount; i++ {
			go func() {
				defer ec.wg.Done()
				ec.handleMessage(c)
			}()
		}

		ec.lggr.Infow("Coordinator started")
		return nil
	})
}

func (ec *Coordinator) Close() error {
	return ec.StopOnce("executor.Coordinator", func() error {
		ec.lggr.Infow("Coordinator stopping")

		// Cancel context to signal all goroutines to stop
		if ec.cancel != nil {
			ec.cancel()
		}

		// Close channel to signal workers to stop
		close(ec.workerPoolTasks)

		// Wait for all goroutines to finish
		ec.wg.Wait()

		// Update running state to reflect in healthcheck and readiness
		ec.running.Store(false)

		ec.lggr.Infow("Coordinator stopped")
		return nil
	})
}

func (ec *Coordinator) runStorageStream(ctx context.Context) {
	indexerResults, componentErrors, err := ec.messageSubscriber.Start(ctx)
	if err != nil {
		ec.lggr.Errorw("failed to start ccv result streamer", "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			ec.lggr.Infow("Coordinator exiting")
			return
		case e, ok := <-componentErrors:
			if !ok {
				ec.lggr.Errorw("coordinator component errors channel closed")
			} else {
				ec.lggr.Errorw("error in coordinator component", "error", e)
			}
		case streamResult, ok := <-indexerResults:
			if !ok {
				ec.lggr.Warnw("streamerResults closed")
				// indexerResults channel will only close if context is done.
				return
			}

			msg := streamResult.Message
			err := ec.executor.CheckValidMessage(ctx, msg)
			if err != nil {
				ec.lggr.Errorw("invalid message, skipping", "error", err, "message", msg)
				continue
			}

			id := msg.MustMessageID()

			if ec.delayedMessageHeap.Has(id) {
				ec.lggr.Infow("message already in delayed heap, skipping", "messageID", id)
				continue
			}
			if ec.inFlightHas(id) {
				ec.lggr.Infow("message already in flight, skipping", "messageID", id)
				continue
			}

			// get message delay from leader elector using indexer's ingestion timestamp
			readyTimestamp := ec.leaderElector.GetReadyTimestamp(
				id,
				msg.DestChainSelector,
				streamResult.Metadata.IngestionTimestamp)

			ec.lggr.Infow("pushing message to delayed heap",
				"messageID", id,
				"ingestionTimestamp", streamResult.Metadata.IngestionTimestamp,
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
	}
}

func (ec *Coordinator) runProcessingLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	reportingTicker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	defer reportingTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
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
				ec.inFlightAdd(payload.MessageID)
				// If the channel is full, we will block here, but messages will continue to be accumulate in the heap.
				ec.workerPoolTasks <- payload
			}
		case <-reportingTicker.C:
			ec.monitoring.Metrics().RecordMessageHeapSize(ctx, int64(ec.delayedMessageHeap.Len()))
		}
	}
}

func (ec *Coordinator) handleMessage(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-ec.workerPoolTasks:
			if !ok {
				return
			}
			ec.processPayload(ctx, payload)
		}
	}
}

func (ec *Coordinator) processPayload(ctx context.Context, payload message_heap.MessageWithTimestamps) {
	defer ec.inFlightRemove(payload.MessageID)
	currentTime := ec.timeProvider.GetTime()
	if currentTime.After(payload.ExpiryTime) {
		ec.lggr.Infow("message has expired", "messageID", payload.MessageID)
		ec.monitoring.Metrics().IncrementExpiredMessages(ctx)
		return
	}

	message, id := *payload.Message, payload.MessageID

	ec.lggr.Infow("processing message with ID", "messageID", id)

	shouldRetry, err := ec.executor.HandleMessage(ctx, message)
	if shouldRetry {
		ec.lggr.Infow("message should be retried, putting back in heap", "messageID", id)
		ec.delayedMessageHeap.Push(message_heap.MessageWithTimestamps{
			Message:       &message,
			ReadyTime:     payload.ReadyTime.Add(payload.RetryInterval),
			ExpiryTime:    payload.ExpiryTime,
			RetryInterval: payload.RetryInterval,
			MessageID:     id,
		})
	}
	if err != nil {
		ec.lggr.Errorw("failed to handle message", "messageID", id, "error", err)
		ec.monitoring.Metrics().IncrementMessagesProcessingFailed(ctx)
	} else {
		ec.monitoring.Metrics().IncrementMessagesProcessed(ctx)
	}
}

func (ec *Coordinator) inFlightAdd(id protocol.Bytes32) {
	ec.inFlightMu.Lock()
	defer ec.inFlightMu.Unlock()
	ec.inFlight[id] = struct{}{}
}

func (ec *Coordinator) inFlightRemove(id protocol.Bytes32) {
	ec.inFlightMu.Lock()
	defer ec.inFlightMu.Unlock()
	delete(ec.inFlight, id)
}

func (ec *Coordinator) inFlightHas(id protocol.Bytes32) bool {
	ec.inFlightMu.RLock()
	defer ec.inFlightMu.RUnlock()
	_, ok := ec.inFlight[id]
	return ok
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

	services.CopyHealth(report, ec.executor.HealthReport())
	return report
}

// Name returns the fully qualified name of the coordinator.
func (ec *Coordinator) Name() string {
	return "executor.Coordinator"
}
