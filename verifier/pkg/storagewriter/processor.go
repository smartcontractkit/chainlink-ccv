package storagewriter

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
	// defaultPollInterval is how frequently the storage writer polls for new jobs. It
	// applies only to the legacy polling loop, which NewProcessorWithPollInterval selects;
	// NewProcessor waits for a signal instead.
	defaultPollInterval = 500 * time.Millisecond
	// defaultPendingFallbackInterval is how often the signal-driven loop polls for pending
	// work anyway. It is the liveness net for jobs that become available without an
	// in-process signal, so it bounds how late such a job can be picked up.
	defaultPendingFallbackInterval = jobqueue.DefaultPendingFallbackInterval
	// defaultStaleReclaimInterval is how often stale locks are swept. Stale work is
	// produced by the passage of time, so no signal can announce it.
	//
	// Worst-case reclaim is this interval plus the queue's LockDuration, which
	// verifier/pkg/coordinator.go sets to 1 minute for this queue.
	defaultStaleReclaimInterval = 2 * time.Minute
	// defaultCleanupInterval is how frequently the storage writer cleans up archived jobs.
	defaultCleanupInterval = 4 * time.Hour
	// defaultRetentionPeriod is how long archived jobs are kept before deletion.
	defaultRetentionPeriod = 30 * 24 * time.Hour // 30 days
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

// Processor handles batching and writing CCVNodeData to the offchain storage.
// It represents the final stage (3rd step) in the verifier processing pipeline.
//
// We assume here that all failures are transient and can be retried. (e.g. network issues).
// Therefore, on failure, we schedule a retry after a configured retryDelay.
type Processor struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	lggr           logger.Logger
	verifierID     string
	monitoring     verifier.Monitoring
	messageTracker verifier.MessageLatencyTracker

	storage     protocol.CCVNodeDataWriter
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Configuration
	pollInterval    time.Duration
	cleanupInterval time.Duration
	retentionPeriod time.Duration
	batchSize       int
	retryDelay      time.Duration

	// forcePolling keeps the legacy poll loop even when the queue can signal.
	// NewProcessorWithPollInterval sets it, so every caller written against the polling
	// behavior keeps exactly that behavior.
	forcePolling bool
	// pendingFallbackInterval and staleReclaimInterval drive the signal-driven loop.
	pendingFallbackInterval time.Duration
	staleReclaimInterval    time.Duration
}

// NewProcessor creates a storage writer that waits for the result queue to signal new
// work, and polls at defaultPendingFallbackInterval as a liveness net.
func NewProcessor(
	lggr logger.Logger,
	verifierID string,
	monitoring verifier.Monitoring,
	messageTracker verifier.MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config verifier.CoordinatorConfig,
	opts ...Option,
) (*Processor, error) {
	p := newProcessor(lggr, verifierID, monitoring, messageTracker, storage, resultQueue, config, defaultPollInterval)
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// NewProcessorWithPollInterval creates a storage writer that always polls, at the given
// interval, even when the queue can signal.
func NewProcessorWithPollInterval(
	lggr logger.Logger,
	verifierID string,
	monitoring verifier.Monitoring,
	messageTracker verifier.MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config verifier.CoordinatorConfig,
	pollInterval time.Duration,
) (*Processor, error) {
	p := newProcessor(lggr, verifierID, monitoring, messageTracker, storage, resultQueue, config, pollInterval)
	p.forcePolling = true
	return p, nil
}

func newProcessor(
	lggr logger.Logger,
	verifierID string,
	monitoring verifier.Monitoring,
	messageTracker verifier.MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config verifier.CoordinatorConfig,
	pollInterval time.Duration,
) *Processor {
	storageBatchSize, _, retryDelay := configWithDefaults(lggr, config)

	return &Processor{
		lggr:                    lggr,
		verifierID:              verifierID,
		monitoring:              monitoring,
		messageTracker:          messageTracker,
		storage:                 storage,
		resultQueue:             resultQueue,
		retryDelay:              retryDelay,
		pollInterval:            pollInterval,
		cleanupInterval:         defaultCleanupInterval,
		retentionPeriod:         defaultRetentionPeriod,
		batchSize:               storageBatchSize,
		pendingFallbackInterval: defaultPendingFallbackInterval,
		staleReclaimInterval:    defaultStaleReclaimInterval,
		stopCh:                  make(chan struct{}),
	}
}

func (s *Processor) Start(context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.run()
		})
		return nil
	})
}

func (s *Processor) Close() error {
	return s.StopOnce(s.Name(), func() error {
		close(s.stopCh)
		s.wg.Wait()
		return nil
	})
}

func (s *Processor) run() {
	ctx, cancel := s.stopCh.NewCtx()
	defer cancel()

	// Signal-driven consumption needs both a queue that offers the capability and a live
	// channel. A decorator wrapping a queue that cannot signal satisfies the interface but
	// returns nil, which means "not supported".
	sdq, ok := s.resultQueue.(jobqueue.SignalDrivenQueue[protocol.VerifierNodeResult])
	if s.forcePolling || !ok || sdq.Signals() == nil {
		s.lggr.Infow("Storage writer queue consumption mode",
			"mode", "polling",
			"forced", s.forcePolling,
			"capable", ok,
			"pollInterval", s.pollInterval,
		)
		s.runPolling(ctx)
		return
	}

	s.lggr.Infow("Storage writer queue consumption mode",
		"mode", "signal-driven",
		"pendingFallbackInterval", s.pendingFallbackInterval,
		"staleReclaimInterval", s.staleReclaimInterval,
	)
	s.runSignalDriven(ctx, sdq)
}

// runPolling is the legacy loop. It consumes both pending and stale jobs on one timer.
func (s *Processor) runPolling(ctx context.Context) {
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(s.cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.lggr.Infow("Processor close signal received, shutting down")
			return

		case <-ticker.C:
			if err := s.processBatch(ctx); err != nil {
				s.lggr.Errorw("Error processing batch", "error", err)
			}

		case <-cleanupTicker.C:
			if err := s.cleanup(ctx); err != nil {
				s.lggr.Errorw("Error running cleanup", "error", err)
			}
		}
	}
}

// runSignalDriven waits for the queue to report new work, and keeps two timers as the
// paths that no signal can cover: a fallback poll for pending jobs, and a sweep for stale
// locks.
func (s *Processor) runSignalDriven(ctx context.Context, sdq jobqueue.SignalDrivenQueue[protocol.VerifierNodeResult]) {
	signals := sdq.Signals()

	pendingTicker := jobqueue.NewJitteredTicker(s.pendingFallbackInterval, jobqueue.DefaultTickerJitter)
	defer pendingTicker.Stop()
	staleTicker := jobqueue.NewJitteredTicker(s.staleReclaimInterval, jobqueue.DefaultTickerJitter)
	defer staleTicker.Stop()

	cleanupTicker := time.NewTicker(s.cleanupInterval)
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
			s.lggr.Infow("Processor close signal received, shutting down")
			return

		case <-signals:
			s.consumePendingBatch(ctx, sdq, pendingRearm)
		case <-pendingRearm:
			s.consumePendingBatch(ctx, sdq, pendingRearm)
		case <-pendingTicker.C():
			pendingTicker.Reset()
			s.consumePendingBatch(ctx, sdq, pendingRearm)

		case <-staleRearm:
			s.reclaimStaleBatch(ctx, sdq, staleRearm)
		case <-staleTicker.C():
			staleTicker.Reset()
			s.reclaimStaleBatch(ctx, sdq, staleRearm)

		case <-cleanupTicker.C:
			if err := s.cleanup(ctx); err != nil {
				s.lggr.Errorw("Error running cleanup", "error", err)
			}
		}
	}
}

// consumePendingBatch consumes one batch of pending jobs and asks for another look when
// the batch was not empty.
//
// The re-arm rule is "the last look found something", not "the batch was full". Signals
// coalesce, so one token can stand for any amount of work, and a full batch is not a
// reliable marker either: runConsumeQuery drops rows that fail to deserialize, so a batch
// can come back short even when the query returned a full one. Re-arming on any progress
// covers both. It cannot spin, because consumed jobs leave the pending state.
func (s *Processor) consumePendingBatch(
	ctx context.Context,
	sdq jobqueue.SignalDrivenQueue[protocol.VerifierNodeResult],
	rearm chan<- struct{},
) {
	consumeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	jobs, err := sdq.ConsumePending(consumeCtx, s.batchSize)
	cancel()
	if err != nil {
		s.lggr.Errorw("Failed to consume pending storage write jobs", "error", err)
		return
	}
	if len(jobs) == 0 {
		return
	}

	// Re-arm before processing, so a batch that fails part way still gets another look.
	select {
	case rearm <- struct{}{}:
	default:
	}

	if err := s.processJobs(ctx, jobs); err != nil {
		s.lggr.Errorw("Error processing batch", "error", err)
	}
}

// reclaimStaleBatch reclaims one batch of stale locks, and asks for another look when the
// batch was not empty so a large backlog left by a crash drains at full speed instead of
// one batch per sweep.
func (s *Processor) reclaimStaleBatch(
	ctx context.Context,
	sdq jobqueue.SignalDrivenQueue[protocol.VerifierNodeResult],
	rearm chan<- struct{},
) {
	consumeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	jobs, err := sdq.ReclaimStale(consumeCtx, s.batchSize)
	cancel()
	if err != nil {
		s.lggr.Errorw("Failed to reclaim stale storage write jobs", "error", err)
		return
	}
	if len(jobs) == 0 {
		return
	}

	select {
	case rearm <- struct{}{}:
	default:
	}

	if err := s.processJobs(ctx, jobs); err != nil {
		s.lggr.Errorw("Error processing reclaimed batch", "error", err)
	}
}

func (s *Processor) processBatch(ctx context.Context) error {
	// Consume batch of results from queue
	consumeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	defer cancel()

	jobs, err := s.resultQueue.Consume(consumeCtx, s.batchSize)
	if err != nil {
		return fmt.Errorf("failed to consume from result queue: %w", err)
	}

	return s.processJobs(ctx, jobs)
}

// processJobs writes a batch of results that has already been consumed and locked. Every
// consumption path funnels through it, so pending jobs and reclaimed stale jobs are
// handled identically.
func (s *Processor) processJobs(ctx context.Context, jobs []jobqueue.Job[protocol.VerifierNodeResult]) error {
	if len(jobs) == 0 {
		return nil // No work to do
	}

	s.lggr.Debugw("Processing verification results batch",
		"batchSize", len(jobs),
	)

	// Extract results for writing
	results := make([]protocol.VerifierNodeResult, len(jobs))
	for i, job := range jobs {
		carrier := propagation.MapCarrier{
			"traceparent": job.Payload.TraceParent,
		}
		parentCtx := otel.GetTextMapPropagator().Extract(context.WithoutCancel(ctx), carrier)

		payload := job.Payload
		var span oteltrace.Span
		payload.TraceContext, span = s.monitoring.Tracing().StartMessageSpan(
			parentCtx, monitoring.StorageWriterWriteSpanName(s.verifierID), job.Payload.MessageID,
			attribute.String(tracing.VerifierIDKey, s.verifierID),
			attribute.String(tracing.JobIDKey, job.ID),
		)
		span.AddEvent(monitoring.EventJobDiscovered,
			oteltrace.WithAttributes(
				attribute.String(tracing.JobIDKey, job.ID),
				attribute.String(tracing.SourceChainNameKey, job.Payload.Message.SourceChainSelector.ChainName()),
				attribute.String(tracing.SourceChainSelectorKey, job.Payload.Message.SourceChainSelector.String()),
				attribute.String(tracing.DestChainNameKey, job.Payload.Message.DestChainSelector.ChainName()),
				attribute.String(tracing.DestChainSelectorKey, job.Payload.Message.DestChainSelector.String()),
			),
		)
		// results must carry the span-started context (not the raw extracted
		// one) - every later lookup below reads results[i].TraceContext, and
		// it must resolve to the real, live write span rather than the
		// non-recording placeholder OTel returns for an extracted-but-unstarted
		// remote context.
		results[i] = payload
	}
	defer func() {
		for _, result := range results {
			tracing.SpanFromContext(result.TraceContext).End()
		}
	}()

	// Write batch to storage
	writeResults, err := s.storage.WriteCCVNodeData(ctx, results)
	if err != nil && len(writeResults) == 0 {
		// Catastrophic failure - no results returned at all
		s.lggr.Errorw("Failed to write CCV data batch to storage with no results, scheduling retry",
			"error", err,
			"batchSize", len(results),
			"retryDelay", s.retryDelay,
		)

		// Schedule retry for all jobs in this batch
		errorMap := make(map[string]error)
		jobIDs := make([]string, len(jobs))
		for i, job := range jobs {
			jobIDs[i] = job.ID
			errorMap[job.ID] = err

			span := tracing.SpanFromContext(results[i].TraceContext)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.AddEvent(monitoring.EventRetryScheduled, oteltrace.WithAttributes(
				attribute.String(tracing.DelayKey, s.retryDelay.String()),
			))
			s.messageMetrics(results[i].Message).IncrementMessageFailure(
				ctx,
				monitoring.MessageTransitionStageStorageWrite,
				true,
				monitoring.ClassifyError(err))
			s.messageMetrics(results[i].Message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStageStorageWrite,
				monitoring.MessageTransitionOutcomeRetryScheduled,
				monitoring.MessageTransitionReasonBatchWriteFailed)
		}

		retryCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
		defer cancel()

		if retryErr := s.resultQueue.Retry(retryCtx, s.retryDelay, errorMap, jobIDs...); retryErr != nil {
			s.lggr.Errorw("Failed to schedule retry for CCV data batch",
				"error", retryErr,
				"batchSize", len(jobs),
			)
		}
		return err
	}

	// Process individual results
	successfulJobs := make([]string, 0, len(jobs))
	retriableFailedJobs := make([]string, 0)
	nonRetriableFailedJobs := make([]string, 0)
	failedErrorMap := make(map[string]error)
	successfulResults := make([]protocol.VerifierNodeResult, 0, len(results))

	for i, writeResult := range writeResults {
		if i >= len(jobs) {
			s.lggr.Errorw("Received more write results than jobs submitted",
				"writeResultsCount", len(writeResults),
				"jobsCount", len(jobs),
			)
			break
		}

		job := jobs[i]
		jobID := job.ID
		messageID := writeResult.Input.MessageID.String()
		span := tracing.SpanFromContext(results[i].TraceContext)

		if writeResult.Status == protocol.WriteSuccess {
			successfulJobs = append(successfulJobs, jobID)
			successfulResults = append(successfulResults, writeResult.Input)
			// PER-MESSAGE LOG (success): terminal; verification result persisted to storage.
			s.lggr.Infow("Write succeeded for message", protocol.LogTypeKey, protocol.LogTypeMessageSuccess, protocol.LogKeyMessageID, messageID, protocol.LogKeyJobID, jobID)

			span.AddEvent(monitoring.EventWriteSucceeded)
			s.messageMetrics(writeResult.Input.Message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStageStorageWrite,
				monitoring.MessageTransitionOutcomeSucceeded,
				monitoring.MessageTransitionReasonNone)
		} else {
			span.RecordError(writeResult.Error, oteltrace.WithAttributes(attribute.Bool(tracing.RetryableKey, writeResult.Retryable)))
			span.SetStatus(codes.Error, writeResult.Error.Error())
			if writeResult.Retryable {
				s.messageMetrics(writeResult.Input.Message).IncrementMessageFailure(
					ctx,
					monitoring.MessageTransitionStageStorageWrite,
					true,
					monitoring.ClassifyError(writeResult.Error))
				s.messageMetrics(writeResult.Input.Message).IncrementMessageTransition(
					ctx,
					monitoring.MessageTransitionStageStorageWrite,
					monitoring.MessageTransitionOutcomeRetryScheduled,
					monitoring.MessageTransitionReasonStorageWriteFailed)
				retriableFailedJobs = append(retriableFailedJobs, jobID)
				failedErrorMap[jobID] = writeResult.Error
				s.lggr.Errorw("Write failed for message (retryable)",
					protocol.LogKeyMessageID, messageID,
					protocol.LogKeyJobID, jobID,
					"error", writeResult.Error,
				)

				span.AddEvent(monitoring.EventRetryScheduled, oteltrace.WithAttributes(
					attribute.String(tracing.DelayKey, s.retryDelay.String()),
				))
			} else {
				s.messageMetrics(writeResult.Input.Message).IncrementMessageFailure(
					ctx,
					monitoring.MessageTransitionStageStorageWrite,
					false,
					monitoring.ClassifyError(writeResult.Error))
				s.messageMetrics(writeResult.Input.Message).IncrementMessageTransition(
					ctx,
					monitoring.MessageTransitionStageStorageWrite,
					monitoring.MessageTransitionOutcomePermanentlyFailed,
					monitoring.MessageTransitionReasonStorageWriteFailed)
				nonRetriableFailedJobs = append(nonRetriableFailedJobs, jobID)
				failedErrorMap[jobID] = writeResult.Error
				s.lggr.Errorw("Write failed for message (non-retryable)",
					protocol.LogKeyMessageID, messageID,
					protocol.LogKeyJobID, jobID,
					"error", writeResult.Error,
				)
			}
		}
	}

	// Log summary
	s.lggr.Debugw("CCV data batch write completed",
		"totalRequests", len(jobs),
		"successful", len(successfulJobs),
		"retriableFailed", len(retriableFailedJobs),
		"nonRetriableFailed", len(nonRetriableFailedJobs),
	)

	// Schedule retry for retriable failed jobs only
	if len(retriableFailedJobs) > 0 {
		s.lggr.Infow("Scheduling retry for failed writes",
			"retriableFailedCount", len(retriableFailedJobs),
			"retryDelay", s.retryDelay,
		)

		retryCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
		defer cancel()

		if retryErr := s.resultQueue.Retry(retryCtx, s.retryDelay, failedErrorMap, retriableFailedJobs...); retryErr != nil {
			s.lggr.Errorw("Failed to schedule retry for failed writes",
				"error", retryErr,
				"retriableFailedCount", len(retriableFailedJobs),
			)
		}
	}

	// Mark non-retryable failed jobs as failed permanently
	if len(nonRetriableFailedJobs) > 0 {
		s.lggr.Warnw("Marking non-retryable failed jobs as failed",
			"nonRetriableFailedCount", len(nonRetriableFailedJobs),
		)

		failCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
		defer cancel()

		if failErr := s.resultQueue.Fail(failCtx, failedErrorMap, nonRetriableFailedJobs...); failErr != nil {
			s.lggr.Errorw("Failed to mark jobs as failed",
				"error", failErr,
				"nonRetriableFailedCount", len(nonRetriableFailedJobs),
			)
		}
	}

	// Process successful jobs
	if len(successfulJobs) == 0 {
		s.lggr.Debugw("No successful writes in this batch, skipping completion")
		return nil
	}

	// Mark successful jobs as completed in queue
	completeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	defer cancel()

	if err := s.resultQueue.Complete(completeCtx, successfulJobs...); err != nil {
		s.lggr.Errorw("Failed to complete jobs in queue",
			"error", err,
			"successfulCount", len(successfulJobs),
		)
		// Continue anyway - data is written, tracking will catch up
	}

	// Track message latencies
	s.messageTracker.TrackMessageLatencies(ctx, successfulResults)

	return nil
}

func (s *Processor) messageMetrics(message protocol.Message) verifier.MetricLabeler {
	return s.monitoring.Metrics().With(
		"source_chain", message.SourceChainSelector.String(),
		"source_chain_name", message.SourceChainSelector.ChainName(),
		"dest_chain", message.DestChainSelector.String(),
		"dest_chain_name", message.DestChainSelector.ChainName(),
		"verifier_id", s.verifierID,
	)
}

func (s *Processor) cleanup(ctx context.Context) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	defer cancel()

	// Cleanup archived jobs older than retention period
	deleted, err := s.resultQueue.Cleanup(cleanupCtx, s.retentionPeriod)
	if err != nil {
		return fmt.Errorf("failed to cleanup result queue: %w", err)
	}

	if deleted > 0 {
		s.lggr.Infow("Cleaned up archived results",
			"count", deleted,
			"retentionPeriod", s.retentionPeriod,
		)
	}

	return nil
}

func (s *Processor) Name() string {
	return fmt.Sprintf("verifier.Processor[%s]", s.verifierID)
}

func (s *Processor) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()
	return report
}

func configWithDefaults(lggr logger.Logger, config verifier.CoordinatorConfig) (int, time.Duration, time.Duration) {
	storageBatchSize := config.StorageBatchSize
	if config.StorageBatchSize <= 0 {
		storageBatchSize = 50
		lggr.Debugw("Using default StorageBatchSize", "value", config.StorageBatchSize)
	}

	storageBatchTimeout := config.StorageBatchTimeout
	if storageBatchTimeout <= 0 {
		storageBatchTimeout = 1 * time.Second
		lggr.Debugw("Using default StorageBatchTimeout", "value", config.StorageBatchTimeout)
	}

	retryDelay := config.StorageRetryDelay
	if retryDelay <= 0 {
		retryDelay = 2 * time.Second
		lggr.Debugw("Using default StorageRetryDelay", "value", retryDelay)
	}

	return storageBatchSize, storageBatchTimeout, retryDelay
}

var (
	_ services.Service        = (*Processor)(nil)
	_ protocol.HealthReporter = (*Processor)(nil)
)
