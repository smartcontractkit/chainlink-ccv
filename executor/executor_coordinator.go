package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/message_heap"
	execmonitoring "github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// Coordinator is the main executor coordinator that manages the timing of a message lifecycle.
// It is responsible for reading messages from a source, managing a decentralized delay mechanism,
// dispatching them to workers for execution, and retrying if necessary.
type Coordinator struct {
	services.StateMachine
	wg                        sync.WaitGroup
	executorID                string
	executor                  Executor
	messageSubscriber         MessageSubscriber
	leaderElector             LeaderElector
	lggr                      logger.Logger
	monitoring                execmonitoring.Monitoring
	workerPoolTasks           chan message_heap.MessageWithTimestamps
	cancel                    context.CancelFunc
	delayedMessageHeap        message_heap.MessageHeap
	inFlight                  map[protocol.Bytes32]messageLane
	inFlightMu                sync.RWMutex
	reportedLanes             map[messageLane]struct{}
	running                   atomic.Bool
	expiryDuration            time.Duration
	timeProvider              common.TimeProvider
	workerCount               int
	dataNotReadyRetryInterval time.Duration
}

type messageLane struct {
	source protocol.ChainSelector
	dest   protocol.ChainSelector
}

// NewCoordinator creates a new executor coordinator.
func NewCoordinator(lggr logger.Logger, executorID string, executor Executor, messageSubscriber MessageSubscriber, leaderElector LeaderElector, monitoring execmonitoring.Monitoring, expiryDuration time.Duration, timeProvider common.TimeProvider, workerCount int, dataNotReadyRetryInterval time.Duration) (*Coordinator, error) {
	if dataNotReadyRetryInterval <= 0 {
		dataNotReadyRetryInterval = DefaultDataNotReadyRetryInterval
	}
	ec := &Coordinator{
		lggr:              lggr,
		executorID:        executorID,
		executor:          executor,
		messageSubscriber: messageSubscriber,
		leaderElector:     leaderElector,
		monitoring:        monitoring,
		workerPoolTasks:   make(chan message_heap.MessageWithTimestamps),
		// cancel and delayedMessageHeap are initialized in Start()
		// running, wg, and services.StateMachine default initialization is fine.
		expiryDuration:            expiryDuration,
		timeProvider:              timeProvider,
		workerCount:               workerCount,
		dataNotReadyRetryInterval: dataNotReadyRetryInterval,
	}

	if err := ec.validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	return ec, nil
}

// Start starts the executor coordinator. Context is required to be passed in to satisfy the ServiceCtx interface.
func (ec *Coordinator) Start(ctx context.Context) error {
	return ec.StartOnce("executor.Coordinator", func() error {
		c, cancel := context.WithCancel(context.Background())
		ec.cancel = cancel

		if err := ec.executor.Start(c); err != nil {
			ec.lggr.Errorf("unable to start executor coordinator due to error: %w", err)
			return err
		}
		ec.delayedMessageHeap = *message_heap.NewMessageHeap(ec.lggr)
		ec.inFlight = make(map[protocol.Bytes32]messageLane)
		ec.reportedLanes = make(map[messageLane]struct{})
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
		for i := 0; i < ec.workerCount; i++ {
			ec.wg.Go(func() {
				ec.handleMessage(c)
			})
		}

		ec.lggr.Infow("Coordinator started")
		ec.monitoring.RecordServiceStarted(ctx)

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

		// Wait for all goroutines to finish
		ec.wg.Wait()

		// It is safe to close the channel once all goroutines have stopped.
		close(ec.workerPoolTasks)

		executorCloseErr := ec.executor.Close()
		if executorCloseErr != nil {
			ec.lggr.Errorw("failed to close executor", "error", executorCloseErr)
		}

		// Update running state to reflect in healthcheck and readiness
		ec.running.Store(false)

		ec.lggr.Infow("Coordinator stopped")
		return executorCloseErr
	})
}

func (ec *Coordinator) runStorageStream(ctx context.Context) {
	indexerResults, componentErrors, err := ec.messageSubscriber.Start(ctx)
	if err != nil {
		ec.lggr.Errorw("failed to start ccv result streamer, shutting down coordinator", "error", err)
		ec.cancel()
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
			metrics := ec.metricsForMessage(msg)
			err := ec.executor.CheckValidMessage(ctx, msg)
			if err != nil {
				ec.lggr.Errorw("invalid message, skipping", "error", err, "message", msg)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageDiscovery,
					execmonitoring.MessageTransitionOutcomeSkipped,
					execmonitoring.MessageTransitionReasonInvalidMessage)
				metrics.IncrementMessageFailure(
					ctx,
					execmonitoring.MessageTransitionStageDiscovery,
					false,
					execmonitoring.MessageFailureClassInvalidMessage)
				continue
			}

			id := msg.MustMessageID()

			if ec.delayedMessageHeap.Has(id) {
				ec.lggr.Debugw("message already in delayed heap, skipping", protocol.LogKeyMessageID, id)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					execmonitoring.MessageTransitionOutcomeSkipped,
					execmonitoring.MessageTransitionReasonDuplicate)
				continue
			}
			if ec.inFlightHas(id) {
				ec.lggr.Debugw("message already in flight, skipping", protocol.LogKeyMessageID, id)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					execmonitoring.MessageTransitionOutcomeSkipped,
					execmonitoring.MessageTransitionReasonDuplicate)
				continue
			}

			if !ec.leaderElector.IsExecutorForChain(msg.DestChainSelector) {
				ec.lggr.Debugw("skipping message, executor not in pool for destination chain",
					protocol.LogKeyMessageID, id, protocol.LogKeyChainSel, msg.DestChainSelector)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					execmonitoring.MessageTransitionOutcomeSkipped,
					execmonitoring.MessageTransitionReasonNotExecutor)
				continue
			}

			readyTimestamp, err := ec.leaderElector.GetReadyTimestamp(
				id,
				msg.DestChainSelector,
				streamResult.Metadata.IngestionTimestamp)
			if err != nil {
				ec.lggr.Errorw("leader elector failed for message, skipping", protocol.LogKeyMessageID, id, protocol.LogKeyChainSel, msg.DestChainSelector, "error", err)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					execmonitoring.MessageTransitionOutcomeSkipped,
					execmonitoring.MessageTransitionReasonLeaderElection)
				metrics.IncrementMessageFailure(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					false,
					execmonitoring.MessageFailureClassLeaderElection)
				continue
			}

			retryDelay, err := ec.leaderElector.GetRetryDelay(msg.DestChainSelector)
			if err != nil {
				ec.lggr.Errorw("leader elector retry delay failed for message, skipping", protocol.LogKeyMessageID, id, protocol.LogKeyChainSel, msg.DestChainSelector, "error", err)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					execmonitoring.MessageTransitionOutcomeSkipped,
					execmonitoring.MessageTransitionReasonLeaderElection)
				metrics.IncrementMessageFailure(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					false,
					execmonitoring.MessageFailureClassLeaderElection)
				continue
			}

			ec.lggr.Debugw("pushing message to delayed heap",
				protocol.LogKeyMessageID, id,
				"ingestionTimestamp", streamResult.Metadata.IngestionTimestamp,
				"readyTimestamp", readyTimestamp,
			)

			// Discovery span: marks the moment this instance observed the
			// message. It ends right away rather than staying open across
			// the delay/retry lifecycle (which can span minutes/hours) -
			// each attempt gets its own fresh span (see processPayload),
			// parented off this one via DiscoveryContext/TraceContext so it
			// still lands in the same trace.
			discCtx, discSpan := ec.monitoring.Tracing().StartMessageSpan(
				ctx, execmonitoring.DiscoverySpanName(ec.executorID), id,
				attribute.String(tracing.DestChainSelectorKey, msg.DestChainSelector.String()),
				attribute.String(tracing.SourceChainSelectorKey, msg.SourceChainSelector.String()),
				attribute.String(tracing.IngestionTimestampKey, streamResult.Metadata.IngestionTimestamp.Format(time.RFC3339)),
				attribute.String(tracing.ReadyTimestampKey, readyTimestamp.Format(time.RFC3339)))
			discSpan.AddEvent(execmonitoring.EventMessageDiscovered)
			metrics.IncrementMessageTransition(
				ctx,
				execmonitoring.MessageTransitionStageDiscovery,
				execmonitoring.MessageTransitionOutcomeDiscovered,
				execmonitoring.MessageTransitionReasonNone)

			if !ec.delayedMessageHeap.Push(message_heap.MessageWithTimestamps{
				Message:       &msg,
				IngestionTime: streamResult.Metadata.IngestionTimestamp,
				ReadyTime:     readyTimestamp,
				ExpiryTime:    readyTimestamp.Add(ec.expiryDuration),
				RetryInterval: retryDelay,
				MessageID:     id,
				Attempt:       0,
				TraceContext:  discCtx,
			}) {
				ec.lggr.Debugw("duplicate message rejected by heap", protocol.LogKeyMessageID, id)
				discSpan.AddEvent(execmonitoring.EventDuplicateRejected)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					execmonitoring.MessageTransitionOutcomeSkipped,
					execmonitoring.MessageTransitionReasonDuplicate)
			} else {
				discSpan.AddEvent(execmonitoring.EventMessageScheduled)
				metrics.IncrementMessageTransition(
					ctx,
					execmonitoring.MessageTransitionStageScheduling,
					execmonitoring.MessageTransitionOutcomeScheduled,
					execmonitoring.MessageTransitionReasonNone)
			}
			discSpan.End()
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
			ec.lggr.Infow("Processing loop exiting")
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
				// If the channel is full, we will block here, but messages will continue to accumulate in the heap.
				select {
				case ec.workerPoolTasks <- payload:
					ec.inFlightAdd(payload.MessageID, *payload.Message)
				case <-ctx.Done():
					ec.lggr.Infow("Processing loop dropping payload to exit")
					return
				}
			}
		case <-reportingTicker.C:
			ec.monitoring.Metrics().RecordMessageHeapSize(ctx, int64(ec.delayedMessageHeap.Len()))
			ec.reportQueueMetrics(ctx, ec.timeProvider.GetTime())
		}
	}
}

func (ec *Coordinator) handleMessage(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			ec.lggr.Infow("Message handler exiting")
			return
		case payload, ok := <-ec.workerPoolTasks:
			if ok {
				ec.processPayload(ctx, payload)
			}
		}
	}
}

func (ec *Coordinator) processPayload(ctx context.Context, payload message_heap.MessageWithTimestamps) {
	defer ec.inFlightRemove(payload.MessageID)
	currentTime := ec.timeProvider.GetTime()
	metrics := ec.metricsForMessage(*payload.Message)

	traceCtx := payload.TraceContext
	if traceCtx == nil {
		traceCtx = ctx
	}

	attemptCtx, attemptSpan := ec.monitoring.Tracing().StartMessageSpan(
		traceCtx, execmonitoring.ProcessPayloadSpanName(ec.executorID), payload.MessageID,
		attribute.String(tracing.DestChainSelectorKey, payload.Message.DestChainSelector.String()),
		attribute.String(tracing.DestChainNameKey, payload.Message.DestChainSelector.ChainName()),
		attribute.Int(tracing.AttemptKey, payload.Attempt),
	)
	defer attemptSpan.End()

	if currentTime.After(payload.ExpiryTime) {
		// PER-MESSAGE LOG (failure): terminal; message exceeded its expiry without execution.
		ec.lggr.Infow("message has expired", protocol.LogTypeKey, protocol.LogTypeMessageFailure, protocol.LogKeyMessageID, payload.MessageID)
		metrics.IncrementExpiredMessages(ctx)
		metrics.IncrementMessageTransition(
			ctx,
			execmonitoring.MessageTransitionStageExecution,
			execmonitoring.MessageTransitionOutcomeExpired,
			execmonitoring.MessageTransitionReasonNone)
		attemptSpan.AddEvent(execmonitoring.EventMessageExpired)
		return
	}

	// PER-MESSAGE LOG (status): one per message picked up for an execution attempt.
	ec.lggr.Infow("processing message with ID", protocol.LogTypeKey, protocol.LogTypeMessageStatus, protocol.LogKeyMessageID, payload.MessageID.String())
	metrics.IncrementMessageTransition(
		ctx,
		execmonitoring.MessageTransitionStageExecution,
		execmonitoring.MessageTransitionOutcomeAttempted,
		execmonitoring.MessageTransitionReasonNone)

	shouldRetry, err := ec.executor.HandleMessage(attemptCtx, *payload.Message)
	if err != nil {
		attemptSpan.RecordError(err, oteltrace.WithAttributes(attribute.Bool(tracing.RetryableKey, shouldRetry)))
		attemptSpan.SetStatus(codes.Error, err.Error())
	}
	if shouldRetry {
		ec.scheduleRetry(retryParams{
			payload:      payload,
			message:      *payload.Message,
			id:           payload.MessageID,
			currentTime:  currentTime,
			err:          err,
			attemptCtx:   attemptCtx,
			discoveryCtx: traceCtx,
		})
	} else if err == nil {
		attemptSpan.AddEvent(execmonitoring.EventMessageExecuted)
	}
	metrics.IncrementMessagesProcessing(ctx)
	if err != nil {
		ec.lggr.Errorw("failed to handle message", protocol.LogKeyMessageID, payload.MessageID.String(), "error", err, "shouldRetry", shouldRetry)
		metrics.IncrementMessagesProcessingError(ctx, shouldRetry)
	}
}

// retryParams bundles the inputs scheduleRetry needs to reschedule a message attempt.
type retryParams struct {
	payload      message_heap.MessageWithTimestamps
	message      protocol.Message
	id           protocol.Bytes32
	currentTime  time.Time
	err          error
	attemptCtx   context.Context
	discoveryCtx context.Context
}

// scheduleRetry computes the retry delay/attempt count for a message that should be retried,
// records it on the current attempt span, and pushes the message back onto the delayed heap.
func (ec *Coordinator) scheduleRetry(p retryParams) {
	ec.lggr.Debugw("message should be retried, putting back in heap", protocol.LogKeyMessageID, p.id)

	attempt := p.payload.Attempt
	var delay time.Duration
	if errors.Is(p.err, ErrExecutionContended) {
		// Post-transmit: preserve anti-duplication stagger.
		delay = p.payload.RetryInterval
		attempt = 0
	} else {
		// Pre-transmit (data/state not ready): fast exponential backoff capped at the stagger.
		attempt++
		delay = ec.dataNotReadyBackoff(attempt, p.payload.RetryInterval)
	}
	attemptSpan := tracing.SpanFromContext(p.attemptCtx)
	attemptSpan.AddEvent(execmonitoring.EventRetryScheduled, oteltrace.WithAttributes(
		attribute.String(tracing.DelayKey, delay.String()),
	))
	reason := execmonitoring.MessageTransitionReasonDataNotReady
	if errors.Is(p.err, ErrExecutionContended) {
		reason = execmonitoring.MessageTransitionReasonExecutionContended
	}
	ec.metricsForMessage(p.message).IncrementMessageTransition(p.attemptCtx, execmonitoring.MessageTransitionStageRetry, execmonitoring.MessageTransitionOutcomeRetryScheduled, reason)

	if !ec.delayedMessageHeap.Push(message_heap.MessageWithTimestamps{
		Message:       &p.message,
		IngestionTime: p.payload.IngestionTime,
		ReadyTime:     p.currentTime.Add(delay),
		ExpiryTime:    p.payload.ExpiryTime,
		RetryInterval: p.payload.RetryInterval,
		MessageID:     p.id,
		Attempt:       attempt,
		TraceContext:  p.discoveryCtx,
	}) {
		ec.lggr.Warnw("retry push rejected, message already in heap", protocol.LogKeyMessageID, p.id)
	}
}

func (ec *Coordinator) inFlightAdd(id protocol.Bytes32, message protocol.Message) {
	ec.inFlightMu.Lock()
	defer ec.inFlightMu.Unlock()
	ec.inFlight[id] = messageLane{source: message.SourceChainSelector, dest: message.DestChainSelector}
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

func (ec *Coordinator) metricsForMessage(message protocol.Message) execmonitoring.MetricLabeler {
	return ec.monitoring.Metrics().With(
		"source_chain_selector", message.SourceChainSelector.String(),
		"source_chain_name", message.SourceChainSelector.ChainName(),
		"dest_chain_selector", message.DestChainSelector.String(),
		"dest_chain_name", message.DestChainSelector.ChainName(),
	)
}

func (ec *Coordinator) metricsForLane(lane messageLane) execmonitoring.MetricLabeler {
	return ec.monitoring.Metrics().With(
		"source_chain_selector", lane.source.String(),
		"source_chain_name", lane.source.ChainName(),
		"dest_chain_selector", lane.dest.String(),
		"dest_chain_name", lane.dest.ChainName(),
	)
}

func (ec *Coordinator) reportQueueMetrics(ctx context.Context, now time.Time) {
	pendingByLane := make(map[messageLane]message_heap.LaneStats)
	for _, stats := range ec.delayedMessageHeap.LaneStats() {
		lane := messageLane{source: stats.SourceChainSelector, dest: stats.DestChainSelector}
		pendingByLane[lane] = stats
		ec.reportedLanes[lane] = struct{}{}
	}

	inFlightByLane := make(map[messageLane]int64)
	ec.inFlightMu.RLock()
	for _, lane := range ec.inFlight {
		inFlightByLane[lane]++
		ec.reportedLanes[lane] = struct{}{}
	}
	ec.inFlightMu.RUnlock()

	for lane := range ec.reportedLanes {
		metrics := ec.metricsForLane(lane)
		stats := pendingByLane[lane]
		metrics.RecordMessagesPending(ctx, stats.PendingCount)
		if stats.PendingCount == 0 {
			metrics.RecordOldestPendingMessageAge(ctx, 0)
		} else {
			metrics.RecordOldestPendingMessageAge(ctx, now.Sub(stats.OldestIngestionTime))
		}
		metrics.RecordMessagesInFlight(ctx, inFlightByLane[lane])
	}
}

func (ec *Coordinator) dataNotReadyBackoff(attempt int, capDuration time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 30 {
		attempt = 30
	}
	d := ec.dataNotReadyRetryInterval << (attempt - 1)
	if d <= 0 || (capDuration > 0 && d > capDuration) {
		return capDuration
	}
	return d
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
	appendIfNil(ec.timeProvider, "timeProvider")

	if ec.workerCount <= 0 {
		errs = append(errs, fmt.Errorf("workerCount must be greater than 0"))
	}

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
