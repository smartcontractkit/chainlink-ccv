package taskverifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// defaultTaskPendingFallbackInterval is how often the signal-driven loop polls for
	// pending work anyway. It is the liveness net for tasks that become available without
	// an in-process signal, so it bounds how late such a task can be picked up.
	defaultTaskPendingFallbackInterval = jobqueue.DefaultPendingFallbackInterval
	// defaultTaskStaleReclaimInterval is how often stale locks are swept. Stale work is
	// produced by the passage of time, so no signal can announce it.
	//
	// Worst-case reclaim is this interval plus the queue's LockDuration, which
	// verifier/pkg/coordinator.go sets to 2 minutes for this queue.
	defaultTaskStaleReclaimInterval = 2 * time.Minute
	// defaultTaskCleanupInterval is how frequently the task verifier cleans up archived jobs.
	defaultTaskCleanupInterval = 4 * time.Hour
	// defaultTaskRetentionPeriod is how long archived jobs are kept before deletion.
	defaultTaskRetentionPeriod = 30 * 24 * time.Hour // 30 days
)

// Option adjusts a Processor at construction. It exists so tests can shorten the timers
// without changing any constructor signature.
type Option func(*Processor)

// WithPendingFallbackInterval sets how often the signal-driven loop polls for pending work.
func WithPendingFallbackInterval(d time.Duration) Option {
	return func(p *Processor) {
		if d > 0 {
			p.pendingFallbackInterval = d
		}
	}
}

// WithStaleReclaimInterval sets how often stale locks are swept.
func WithStaleReclaimInterval(d time.Duration) Option {
	return func(p *Processor) {
		if d > 0 {
			p.staleReclaimInterval = d
		}
	}
}

// Processor is responsible for processing read messages from Services,
// verifying them using the provided verifier.Verifier, and sending the results to Processor via the result queue.
// It's the second stage in the verifier processing pipeline.
// It spawns a goroutine per source chain to handle verification concurrently and independently.
// Retries are handled for individual messages based on the verification result. General idea is very similar to
// Processor, but here verifier.Verifier decides whether the error is retryable or not and what delay should be set.
// That way we give verifier.Verifier who is aware of the business logic more control over retry behavior.
type Processor struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	lggr           logger.Logger
	verifierID     string
	monitoring     verifier.Monitoring
	verifier       verifier.Verifier
	messageTracker verifier.MessageLatencyTracker

	// Consumes from ccv_task_verifier_jobs queue
	taskQueue jobqueue.JobQueue[verifier.VerificationTask]
	// Produces to ccv_storage_writer_jobs queue
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Configuration
	cleanupInterval time.Duration
	retentionPeriod time.Duration
	batchSize       int

	// pendingFallbackInterval and staleReclaimInterval drive the signal-driven loop.
	pendingFallbackInterval time.Duration
	staleReclaimInterval    time.Duration
}

// NewProcessor creates a task verifier that waits for the task queue to signal new work,
// and polls at defaultTaskPendingFallbackInterval as a liveness net.
func NewProcessor(
	lggr logger.Logger,
	verifierID string,
	verifier verifier.Verifier,
	monitoring verifier.Monitoring,
	messageTracker verifier.MessageLatencyTracker,
	taskQueue jobqueue.JobQueue[verifier.VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	batchSize int,
	opts ...Option,
) (*Processor, error) {
	p := newProcessor(
		lggr, verifierID, verifier, monitoring, messageTracker, taskQueue, resultQueue, batchSize,
	)
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

func newProcessor(
	lggr logger.Logger,
	verifierID string,
	verifier verifier.Verifier,
	monitoring verifier.Monitoring,
	messageTracker verifier.MessageLatencyTracker,
	taskQueue jobqueue.JobQueue[verifier.VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	batchSize int,
) *Processor {
	return &Processor{
		lggr:                    lggr,
		verifierID:              verifierID,
		monitoring:              monitoring,
		verifier:                verifier,
		messageTracker:          messageTracker,
		taskQueue:               taskQueue,
		resultQueue:             resultQueue,
		cleanupInterval:         defaultTaskCleanupInterval,
		retentionPeriod:         defaultTaskRetentionPeriod,
		batchSize:               batchSize,
		pendingFallbackInterval: defaultTaskPendingFallbackInterval,
		staleReclaimInterval:    defaultTaskStaleReclaimInterval,
		stopCh:                  make(chan struct{}),
	}
}

func (p *Processor) Start(context.Context) error {
	return p.StartOnce(p.Name(), func() error {
		p.wg.Go(func() {
			p.run()
		})
		return nil
	})
}

func (p *Processor) Close() error {
	return p.StopOnce(p.Name(), func() error {
		close(p.stopCh)
		p.wg.Wait()
		return nil
	})
}

func (p *Processor) run() {
	ctx, cancel := p.stopCh.NewCtx()
	defer cancel()

	p.lggr.Infow("Task verifier consuming from job queue",
		"pendingFallbackInterval", p.pendingFallbackInterval,
		"staleReclaimInterval", p.staleReclaimInterval,
	)

	signals := p.taskQueue.Signals()

	pendingTicker := time.NewTicker(p.pendingFallbackInterval)
	defer pendingTicker.Stop()
	staleTicker := time.NewTicker(p.staleReclaimInterval)
	defer staleTicker.Stop()

	cleanupTicker := time.NewTicker(p.cleanupInterval)
	defer cleanupTicker.Stop()

	// pendingRearm and staleRearm let a batch ask for another look straight away, without
	// an inner loop that would starve the other select arms during a long drain.
	//
	// Both are primed here. A signal is only sent by this process, so work that was
	// already waiting at startup has nothing to announce it: rows left behind by a
	// previous run, rows re-published into an ON CONFLICT DO NOTHING, and rows the
	// out-of-process job queue CLI moved back to pending.
	pendingRearm := make(chan struct{}, 1)
	pendingRearm <- struct{}{}
	staleRearm := make(chan struct{}, 1)
	staleRearm <- struct{}{}

	for {
		select {
		case <-ctx.Done():
			p.lggr.Infow("Processor close signal received, shutting down")
			return

		case <-signals:
			p.consumePendingBatch(ctx, pendingRearm)
		case <-pendingRearm:
			p.consumePendingBatch(ctx, pendingRearm)
		case <-pendingTicker.C:
			p.consumePendingBatch(ctx, pendingRearm)

		case <-staleRearm:
			p.reclaimStaleBatch(ctx, staleRearm)
		case <-staleTicker.C:
			p.reclaimStaleBatch(ctx, staleRearm)

		case <-cleanupTicker.C:
			if err := p.cleanup(ctx); err != nil {
				p.lggr.Errorw("Error running cleanup", "error", err)
			}
		}
	}
}

// consumePendingBatch consumes one batch of pending jobs and asks for another look when
// the batch came back full.
//
// Signals coalesce, so one token can stand for any amount of work: a consumer that stopped
// after one batch would leave the rest of a burst waiting for the fallback poll. A full
// batch means the query hit its limit and there is very likely more behind it. A short
// batch means the queue drained, and re-arming there would spend an extra empty query on
// every single arrival.
//
// One gap is accepted here: runConsumeQuery drops rows that fail to deserialize, so a batch
// can come back short even when the query did fill. Those rows are archived on the spot so
// it does not repeat, and the fallback poll picks up whatever was behind them.
//
// It cannot spin, because consumed jobs leave the pending state.
func (p *Processor) consumePendingBatch(
	ctx context.Context,
	rearm chan<- struct{},
) {
	consumeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	jobs, err := p.taskQueue.ConsumePending(consumeCtx, p.batchSize)
	cancel()
	if err != nil {
		p.lggr.Errorw("Failed to consume pending verification tasks", "error", err)
		return
	}
	if len(jobs) == 0 {
		return
	}

	// Re-arm before processing, so a batch that fails part way still gets another look.
	if len(jobs) == p.batchSize {
		select {
		case rearm <- struct{}{}:
		default:
		}
	}

	if err := p.processJobs(ctx, jobs); err != nil {
		p.lggr.Errorw("Error processing verification batch", "error", err)
	}
}

// reclaimStaleBatch reclaims one batch of stale locks, and asks for another look when the
// batch came back full, so a large backlog left by a crash drains at full speed instead of
// one batch per sweep. No signal can announce stale work, so without this the sweep
// interval alone would bound how fast a crash is recovered from.
func (p *Processor) reclaimStaleBatch(
	ctx context.Context,
	rearm chan<- struct{},
) {
	consumeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	jobs, err := p.taskQueue.ReclaimStale(consumeCtx, p.batchSize)
	cancel()
	if err != nil {
		p.lggr.Errorw("Failed to reclaim stale verification tasks", "error", err)
		return
	}
	if len(jobs) == 0 {
		return
	}

	// Re-arm before processing, so a batch that fails part way still gets another look.
	if len(jobs) == p.batchSize {
		select {
		case rearm <- struct{}{}:
		default:
		}
	}

	if err := p.processJobs(ctx, jobs); err != nil {
		p.lggr.Errorw("Error processing reclaimed verification batch", "error", err)
	}
}

// processJobs verifies a batch of tasks that has already been consumed and locked. Every
// consumption path funnels through it, so pending jobs and reclaimed stale jobs are
// handled identically.
func (p *Processor) processJobs(ctx context.Context, jobs []jobqueue.Job[verifier.VerificationTask]) error {
	if len(jobs) == 0 {
		return nil // No work to do
	}

	p.lggr.Debugw("Processing verification tasks batch",
		"batchSize", len(jobs),
	)

	// Extract tasks and build job ID map and task map for metrics
	tasks := make([]verifier.VerificationTask, len(jobs))
	jobIDMap := make(map[string]string)                   // messageID -> jobID
	taskMap := make(map[string]verifier.VerificationTask) // messageID -> task (for accessing timestamps)
	for i, job := range jobs {
		carrier := propagation.MapCarrier{
			"traceparent": job.Payload.TraceParent,
		}
		parentCtx := otel.GetTextMapPropagator().Extract(context.WithoutCancel(ctx), carrier)

		payload := job.Payload
		// Stamp the queue's attempt count onto the task: the persisted payload's own field is
		// stale after a retry, and the policy gate grows its retry delay with each attempt.
		payload.AttemptCount = job.AttemptCount
		messageID, err := protocol.NewBytes32FromString(payload.MessageID)
		if err != nil {
			p.lggr.Errorw("Failed to convert messageID to Bytes32", "error", err, "messageID", payload.MessageID)
			messageID = protocol.Bytes32{}
		}
		var span oteltrace.Span
		payload.TraceContext, span = p.monitoring.Tracing().StartMessageSpan(
			parentCtx, monitoring.TaskVerifierAttemptSpanName(p.verifierID), messageID,
			attribute.String(tracing.VerifierIDKey, p.verifierID),
			attribute.String(tracing.JobIDKey, job.ID),
			attribute.String(tracing.SourceChainSelectorKey, job.Payload.Message.SourceChainSelector.String()),
			attribute.String(tracing.SourceChainNameKey, job.Payload.Message.SourceChainSelector.ChainName()),
			attribute.String(tracing.DestChainSelectorKey, job.Payload.Message.DestChainSelector.String()),
			attribute.String(tracing.DestChainNameKey, job.Payload.Message.DestChainSelector.ChainName()),
		)
		span.AddEvent(monitoring.EventJobDiscovered,
			oteltrace.WithAttributes(
				attribute.String(tracing.JobIDKey, job.ID),
			),
		)

		// tasks/taskMap must carry the span-started context (not the raw
		// extracted one) - everything downstream (VerifyMessages,
		// handleVerificationResults, retry/fail handling) records onto this
		// context, so it must resolve to the real, live attempt span rather
		// than the non-recording placeholder OTel returns for an
		// extracted-but-unstarted remote context.
		tasks[i] = payload
		jobIDMap[payload.MessageID] = job.ID
		taskMap[payload.MessageID] = payload

		// Mark message as seen for E2E latency tracking
		if p.messageTracker != nil {
			p.messageTracker.MarkMessageAsSeen(&tasks[i])
		}
	}

	// Record verification start time for duration tracking
	verificationStartTime := time.Now()

	// Verify messages
	results := p.verifier.VerifyMessages(ctx, tasks)

	// Process verification results
	return p.handleVerificationResults(ctx, results, jobIDMap, taskMap, verificationStartTime)
}

// handleVerificationResults processes verification results, updating job statuses and publishing successful results.
func (p *Processor) handleVerificationResults(
	ctx context.Context,
	results []verifier.VerificationResult,
	jobIDMap map[string]string,
	taskMap map[string]verifier.VerificationTask,
	verificationStartTime time.Time,
) error {
	// Safety net for tasks whose terminal branch below never runs (e.g. no
	// job ID match, or an early return before that task is reached) - the
	// three explicit branches below already end their own span.
	defer func() {
		for _, task := range taskMap {
			tracing.SpanFromContext(task.TraceContext).End()
		}
	}()

	if len(results) == 0 {
		return nil
	}

	var successCount, errorCount int
	successfulResults := make([]protocol.VerifierNodeResult, 0)
	completedJobIDs := make([]string, 0)
	retryJobIDs := make([]string, 0)
	retryErrors := make(map[string]error)
	retryDelays := make(map[string]time.Duration)
	failedJobIDs := make([]string, 0)
	failedErrors := make(map[string]error)

	// Record when results are processed (for queue latency calculation)
	processedAt := time.Now()

	// Process each result
	for _, result := range results {
		messageID := ""
		if result.Error != nil {
			messageID = result.Error.Task.MessageID
		} else if result.Result != nil {
			messageID = result.Result.MessageID.String()
		}

		jobID, exists := jobIDMap[messageID]
		if !exists {
			p.lggr.Errorw("Job ID not found for message", protocol.LogKeyMessageID, messageID)
			continue
		}

		if result.Error != nil {
			errorCount++
			p.handleVerificationError(ctx, *result.Error, jobID, &retryJobIDs, retryErrors, retryDelays, &failedJobIDs, failedErrors)
		} else if result.Result != nil {
			successCount++
			resultCopy := *result.Result
			// Propagate this attempt span's context forward as a W3C
			// traceparent, so storagewriter (across the DB-backed result
			// queue) can reconstruct a real parent-child link instead of
			// only sharing the deterministic trace ID.
			if task, ok := taskMap[messageID]; ok {
				carrier := propagation.MapCarrier{}
				otel.GetTextMapPropagator().Inject(task.TraceContext, carrier)
				resultCopy.TraceParent = carrier.Get("traceparent")
			}
			successfulResults = append(successfulResults, resultCopy)
			completedJobIDs = append(completedJobIDs, jobID)

			// Record successful verification metrics
			message := result.Result.Message
			verificationDuration := time.Since(verificationStartTime)
			p.monitoring.Metrics().
				With(
					"source_chain", message.SourceChainSelector.String(),
					"source_chain_name", message.SourceChainSelector.ChainName(),
					"dest_chain", message.DestChainSelector.String(),
					"dest_chain_name", message.DestChainSelector.ChainName(),
					"verifier_id", p.verifierID,
				).
				IncrementMessagesProcessed(ctx)
			p.messageMetrics(message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStageVerification,
				monitoring.MessageTransitionOutcomeSucceeded,
				monitoring.MessageTransitionReasonNone)

			p.monitoring.Metrics().
				With("source_chain", message.SourceChainSelector.String(), "source_chain_name", message.SourceChainSelector.ChainName(), "verifier_id", p.verifierID).
				RecordMessageVerificationDuration(ctx, verificationDuration)

			// Track verification queue latency (time from push to successful verification, including retries)
			if task, taskExists := taskMap[messageID]; taskExists && !task.PushedToVerificationQueueAt.IsZero() {
				queueLatency := processedAt.Sub(task.PushedToVerificationQueueAt)
				p.monitoring.Metrics().
					With("source_chain", message.SourceChainSelector.String(), "source_chain_name", message.SourceChainSelector.ChainName(), "verifier_id", p.verifierID).
					RecordVerificationQueueLatency(ctx, queueLatency)
			}
		}
	}

	// Publish successful results to ccv_storage_writer_jobs queue
	if len(successfulResults) > 0 {
		publishCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
		defer cancel()

		if err := p.resultQueue.Publish(publishCtx, successfulResults...); err != nil {
			for _, result := range successfulResults {
				if task, ok := taskMap[result.MessageID.String()]; ok {
					tracing.SpanFromContext(task.TraceContext).RecordError(err)
				}
			}
			p.lggr.Errorw("Failed to publish verification results to queue - jobs will remain in processing state and be reclaimed as stale locks",
				"error", err,
				"count", len(successfulResults))
			// Don't complete these jobs - leave them in 'processing' state
			// They will be reclaimed as stale locks and re-processed (re-verified and published)
			// This is a rare case (DB failure), and relying on stale lock reclaim is acceptable
			return fmt.Errorf("failed to publish %d verification results: %w", len(successfulResults), err)
		}
		for _, result := range successfulResults {
			messageID := result.MessageID.String()
			if task, ok := taskMap[messageID]; ok {
				span := tracing.SpanFromContext(task.TraceContext)
				span.AddEvent(monitoring.EventResultPublished)
				span.End()
			}
		}
		p.lggr.Debugw("Published verification results to queue", "count", len(successfulResults))
	}

	// Complete successfully processed jobs
	if len(completedJobIDs) > 0 {
		completeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
		defer cancel()

		if err := p.taskQueue.Complete(completeCtx, completedJobIDs...); err != nil {
			p.lggr.Errorw("Failed to complete jobs - they will remain in processing state and be reclaimed as stale locks",
				"error", err,
				"count", len(completedJobIDs))
			// Don't fail the batch - let stale lock reclaim handle it
			// This is a rare case (DB failure), and we want to continue processing other jobs
		}
	}

	// Retry jobs with retryable errors
	if len(retryJobIDs) > 0 {
		// Group jobs by retry delay to minimize Retry() calls
		jobsByDelay := make(map[time.Duration][]string)
		errorsByDelay := make(map[time.Duration]map[string]error)

		for _, jobID := range retryJobIDs {
			delay := retryDelays[jobID]
			if jobsByDelay[delay] == nil {
				jobsByDelay[delay] = make([]string, 0)
				errorsByDelay[delay] = make(map[string]error)
			}
			jobsByDelay[delay] = append(jobsByDelay[delay], jobID)
			errorsByDelay[delay][jobID] = retryErrors[jobID]
		}

		// Retry jobs grouped by delay
		for delay, jobIDs := range jobsByDelay {
			retryCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)

			if err := p.taskQueue.Retry(retryCtx, delay, errorsByDelay[delay], jobIDs...); err != nil {
				p.lggr.Errorw("Failed to retry jobs - they will remain in processing state and be reclaimed as stale locks",
					"error", err,
					"count", len(jobIDs),
					"delay", delay)
				// Don't fail the batch - let stale lock reclaim handle it
				// This is a rare case (DB failure), and we want to continue processing other jobs
			}
			cancel() // Call cancel immediately after Retry, not deferred
		}
	}

	// Fail jobs with permanent errors
	if len(failedJobIDs) > 0 {
		failCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
		defer cancel()

		if err := p.taskQueue.Fail(failCtx, failedErrors, failedJobIDs...); err != nil {
			p.lggr.Errorw("Failed to mark jobs as failed - they will remain in processing state and be reclaimed as stale locks",
				"error", err,
				"count", len(failedJobIDs))
			// Don't fail the batch - let stale lock reclaim handle it
			// This is a rare case (DB failure), and we want to continue processing other jobs
		}
	}

	p.lggr.Debugw("Verification batch completed",
		"totalResults", len(results),
		"successCount", successCount,
		"errorCount", errorCount,
		"retryCount", len(retryJobIDs),
		"failedCount", len(failedJobIDs))

	return nil
}

// handleVerificationError processes a single verification error, either scheduling retry or marking as permanent failure.
func (p *Processor) handleVerificationError(
	ctx context.Context,
	verificationError verifier.VerificationError,
	jobID string,
	retryJobIDs *[]string,
	retryErrors map[string]error,
	retryDelays map[string]time.Duration,
	failedJobIDs *[]string,
	failedErrors map[string]error,
) {
	message := verificationError.Task.Message

	p.monitoring.Metrics().
		With(
			"source_chain", message.SourceChainSelector.String(),
			"source_chain_name", message.SourceChainSelector.ChainName(),
			"dest_chain", message.DestChainSelector.String(),
			"dest_chain_name", message.DestChainSelector.ChainName(),
			"verifier_id", p.verifierID,
		).
		IncrementMessagesVerificationFailed(ctx)
	p.messageMetrics(message).IncrementMessageFailure(
		ctx,
		monitoring.MessageTransitionStageVerification,
		verificationError.Retryable,
		monitoring.ClassifyError(verificationError.Error))

	// PER-MESSAGE LOG (failure/retryable): one per failed attempt; terminal only when !retryable.
	logType := protocol.LogTypeMessageFailure
	if verificationError.Retryable {
		p.messageMetrics(message).IncrementMessageTransition(
			ctx,
			monitoring.MessageTransitionStageVerification,
			monitoring.MessageTransitionOutcomeRetryScheduled,
			monitoring.MessageTransitionReasonVerificationFailed)
		logType = protocol.LogTypeRetryableMessageFailure
	}
	p.lggr.Errorw("Message verification failed",
		protocol.LogTypeKey, logType,
		"error", verificationError.Error,
		protocol.LogKeyMessageID, verificationError.Task.MessageID,
		protocol.LogKeyNonce, message.SequenceNumber,
		protocol.LogKeySourceChain, message.SourceChainSelector,
		protocol.LogKeyDestChain, message.DestChainSelector,
		"retryable", verificationError.Retryable,
	)

	span := tracing.SpanFromContext(verificationError.Task.TraceContext)
	if verificationError.Error != nil {
		span.RecordError(verificationError.Error, oteltrace.WithAttributes(attribute.Bool(tracing.RetryableKey, verificationError.Retryable)))
		span.SetStatus(codes.Error, verificationError.Error.Error())
	}
	defer span.End()

	if verificationError.Retryable {
		*retryJobIDs = append(*retryJobIDs, jobID)
		retryErrors[jobID] = verificationError.Error
		retryDelays[jobID] = verificationError.DelayOrDefault()

		span.AddEvent(monitoring.EventRetryScheduled, oteltrace.WithAttributes(
			attribute.String(tracing.DelayKey, verificationError.DelayOrDefault().String()),
		))
	} else {
		p.messageMetrics(message).IncrementMessageTransition(
			ctx,
			monitoring.MessageTransitionStageVerification,
			monitoring.MessageTransitionOutcomePermanentlyFailed,
			monitoring.MessageTransitionReasonVerificationFailed)
		// Increment permanent error metric
		p.monitoring.Metrics().
			With(
				"source_chain", message.SourceChainSelector.String(),
				"source_chain_name", message.SourceChainSelector.ChainName(),
				"dest_chain", message.DestChainSelector.String(),
				"dest_chain_name", message.DestChainSelector.ChainName(),
				"verifier_id", p.verifierID,
			).
			IncrementTaskVerificationPermanentErrors(ctx)

		*failedJobIDs = append(*failedJobIDs, jobID)
		failedErrors[jobID] = verificationError.Error
	}
}

func (p *Processor) cleanup(ctx context.Context) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	defer cancel()

	// Cleanup archived jobs older than retention period
	deleted, err := p.taskQueue.Cleanup(cleanupCtx, p.retentionPeriod)
	if err != nil {
		return fmt.Errorf("failed to cleanup task queue: %w", err)
	}

	if deleted > 0 {
		p.lggr.Infow("Cleaned up archived verification tasks",
			"count", deleted,
			"retentionPeriod", p.retentionPeriod,
		)
	}

	return nil
}

func (p *Processor) messageMetrics(message protocol.Message) verifier.MetricLabeler {
	return p.monitoring.Metrics().With(
		"source_chain", message.SourceChainSelector.String(),
		"source_chain_name", message.SourceChainSelector.ChainName(),
		"dest_chain", message.DestChainSelector.String(),
		"dest_chain_name", message.DestChainSelector.ChainName(),
		"verifier_id", p.verifierID,
	)
}

func (p *Processor) Name() string {
	return fmt.Sprintf("verifier.Processor[%s]", p.verifierID)
}

func (p *Processor) HealthReport() map[string]error {
	report := make(map[string]error)
	report[p.Name()] = p.Ready()
	return report
}

var (
	_ services.Service        = (*Processor)(nil)
	_ protocol.HealthReporter = (*Processor)(nil)
)
