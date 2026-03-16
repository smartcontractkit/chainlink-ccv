package verifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// defaultTaskPollInterval is how frequently the task verifier polls for new verification tasks.
	defaultTaskPollInterval = 500 * time.Millisecond
	// defaultTaskCleanupInterval is how frequently the task verifier cleans up archived jobs.
	defaultTaskCleanupInterval = 4 * time.Hour
	// defaultTaskRetentionPeriod is how long archived jobs are kept before deletion.
	defaultTaskRetentionPeriod = 30 * 24 * time.Hour // 30 days
)

// TaskVerifierProcessor is responsible for processing read messages from SourceReaderServices,
// verifying them using the provided Verifier, and sending the results to StorageWriterProcessor via the result queue.
// It's the second stage in the verifier processing pipeline.
// It spawns a goroutine per source chain to handle verification concurrently and independently.
// Retries are handled for individual messages based on the verification result. General idea is very similar to
// StorageWriterProcessor, but here Verifier decides whether the error is retryable or not and what delay should be set.
// That way we give Verifier who is aware of the business logic more control over retry behavior.
type TaskVerifierProcessor struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	lggr           logger.Logger
	verifierID     string
	monitoring     Monitoring
	verifier       Verifier
	messageTracker MessageLatencyTracker

	// Consumes from ccv_task_verifier_jobs queue
	taskQueue jobqueue.JobQueue[VerificationTask]
	// Produces to ccv_storage_writer_jobs queue
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Configuration
	pollInterval    time.Duration
	cleanupInterval time.Duration
	retentionPeriod time.Duration
	batchSize       int
}

func NewTaskVerifierProcessorDB(
	lggr logger.Logger,
	verifierID string,
	verifier Verifier,
	monitoring Monitoring,
	messageTracker MessageLatencyTracker,
	taskQueue jobqueue.JobQueue[VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	batchSize int,
) (*TaskVerifierProcessor, error) {
	return NewTaskVerifierProcessorDBWithPollInterval(
		lggr, verifierID, verifier, monitoring, messageTracker, taskQueue, resultQueue, batchSize, defaultTaskPollInterval,
	)
}

func NewTaskVerifierProcessorDBWithPollInterval(
	lggr logger.Logger,
	verifierID string,
	verifier Verifier,
	monitoring Monitoring,
	messageTracker MessageLatencyTracker,
	taskQueue jobqueue.JobQueue[VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	batchSize int,
	pollInterval time.Duration,
) (*TaskVerifierProcessor, error) {
	p := &TaskVerifierProcessor{
		lggr:            lggr,
		verifierID:      verifierID,
		monitoring:      monitoring,
		verifier:        verifier,
		messageTracker:  messageTracker,
		taskQueue:       taskQueue,
		resultQueue:     resultQueue,
		pollInterval:    pollInterval,
		cleanupInterval: defaultTaskCleanupInterval,
		retentionPeriod: defaultTaskRetentionPeriod,
		batchSize:       batchSize,
		stopCh:          make(chan struct{}),
	}
	return p, nil
}

func (p *TaskVerifierProcessor) Start(context.Context) error {
	return p.StartOnce(p.Name(), func() error {
		p.wg.Go(func() {
			p.run()
		})
		return nil
	})
}

func (p *TaskVerifierProcessor) Close() error {
	return p.StopOnce(p.Name(), func() error {
		close(p.stopCh)
		p.wg.Wait()
		return nil
	})
}

func (p *TaskVerifierProcessor) run() {
	ctx, cancel := p.stopCh.NewCtx()
	defer cancel()

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(p.cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.lggr.Infow("TaskVerifierProcessor close signal received, shutting down")
			return

		case <-ticker.C:
			if err := p.processBatch(ctx); err != nil {
				p.lggr.Errorw("Error processing verification batch", "error", err)
			}

		case <-cleanupTicker.C:
			if err := p.cleanup(ctx); err != nil {
				p.lggr.Errorw("Error running cleanup", "error", err)
			}
		}
	}
}

func (p *TaskVerifierProcessor) processBatch(ctx context.Context) error {
	// Consume batch of tasks from queue
	consumeCtx, cancel := context.WithTimeout(ctx, DefaultJobQueueOperationTimeout)
	defer cancel()

	jobs, err := p.taskQueue.Consume(consumeCtx, p.batchSize)
	if err != nil {
		return fmt.Errorf("failed to consume from task queue: %w", err)
	}

	if len(jobs) == 0 {
		return nil // No work to do
	}

	p.lggr.Debugw("Processing verification tasks batch",
		"batchSize", len(jobs),
	)

	// Extract tasks and build job ID map and task map for metrics
	tasks := make([]VerificationTask, len(jobs))
	jobIDMap := make(map[string]string)          // messageID -> jobID
	taskMap := make(map[string]VerificationTask) // messageID -> task (for accessing timestamps)
	for i, job := range jobs {
		tasks[i] = job.Payload
		jobIDMap[job.Payload.MessageID] = job.ID
		taskMap[job.Payload.MessageID] = job.Payload

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
func (p *TaskVerifierProcessor) handleVerificationResults(
	ctx context.Context,
	results []VerificationResult,
	jobIDMap map[string]string,
	taskMap map[string]VerificationTask,
	verificationStartTime time.Time,
) error {
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
			p.lggr.Errorw("Job ID not found for message", "messageID", messageID)
			continue
		}

		if result.Error != nil {
			errorCount++
			p.handleVerificationError(ctx, *result.Error, jobID, &retryJobIDs, retryErrors, retryDelays, &failedJobIDs, failedErrors)
		} else if result.Result != nil {
			successCount++
			successfulResults = append(successfulResults, *result.Result)
			completedJobIDs = append(completedJobIDs, jobID)

			// Record successful verification metrics
			message := result.Result.Message
			verificationDuration := time.Since(verificationStartTime)
			p.monitoring.Metrics().
				With(
					"source_chain", message.SourceChainSelector.String(),
					"dest_chain", message.DestChainSelector.String(),
					"verifier_id", p.verifierID,
				).
				IncrementMessagesProcessed(ctx)

			p.monitoring.Metrics().
				With("source_chain", message.SourceChainSelector.String(), "verifier_id", p.verifierID).
				RecordMessageVerificationDuration(ctx, verificationDuration)

			// Track verification queue latency (time from push to successful verification, including retries)
			if task, taskExists := taskMap[messageID]; taskExists && !task.PushedToVerificationQueueAt.IsZero() {
				queueLatency := processedAt.Sub(task.PushedToVerificationQueueAt)
				p.monitoring.Metrics().
					With("source_chain", message.SourceChainSelector.String(), "verifier_id", p.verifierID).
					RecordVerificationQueueLatency(ctx, queueLatency)
			}
		}
	}

	// Publish successful results to ccv_storage_writer_jobs queue
	if len(successfulResults) > 0 {
		publishCtx, cancel := context.WithTimeout(ctx, DefaultJobQueueOperationTimeout)
		defer cancel()

		if err := p.resultQueue.Publish(publishCtx, successfulResults...); err != nil {
			p.lggr.Errorw("Failed to publish verification results to queue - jobs will remain in processing state and be reclaimed as stale locks",
				"error", err,
				"count", len(successfulResults))
			// Don't complete these jobs - leave them in 'processing' state
			// They will be reclaimed as stale locks and re-processed (re-verified and published)
			// This is a rare case (DB failure), and relying on stale lock reclaim is acceptable
			return fmt.Errorf("failed to publish %d verification results: %w", len(successfulResults), err)
		}
		p.lggr.Debugw("Published verification results to queue", "count", len(successfulResults))
	}

	// Complete successfully processed jobs
	if len(completedJobIDs) > 0 {
		completeCtx, cancel := context.WithTimeout(ctx, DefaultJobQueueOperationTimeout)
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
			retryCtx, cancel := context.WithTimeout(ctx, DefaultJobQueueOperationTimeout)

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
		failCtx, cancel := context.WithTimeout(ctx, DefaultJobQueueOperationTimeout)
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
func (p *TaskVerifierProcessor) handleVerificationError(
	ctx context.Context,
	verificationError VerificationError,
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
			"dest_chain", message.DestChainSelector.String(),
			"verifier_id", p.verifierID,
		).
		IncrementMessagesVerificationFailed(ctx)

	p.lggr.Errorw("Message verification failed",
		"error", verificationError.Error,
		"messageID", verificationError.Task.MessageID,
		"nonce", message.SequenceNumber,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
		"retryable", verificationError.Retryable,
	)

	if verificationError.Retryable {
		*retryJobIDs = append(*retryJobIDs, jobID)
		retryErrors[jobID] = verificationError.Error
		retryDelays[jobID] = verificationError.DelayOrDefault()
	} else {
		// Increment permanent error metric
		p.monitoring.Metrics().
			With(
				"source_chain", message.SourceChainSelector.String(),
				"dest_chain", message.DestChainSelector.String(),
				"verifier_id", p.verifierID,
			).
			IncrementTaskVerificationPermanentErrors(ctx)

		*failedJobIDs = append(*failedJobIDs, jobID)
		failedErrors[jobID] = verificationError.Error
	}
}

func (p *TaskVerifierProcessor) cleanup(ctx context.Context) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, DefaultJobQueueOperationTimeout)
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

func (p *TaskVerifierProcessor) Name() string {
	return fmt.Sprintf("verifier.TaskVerifierProcessor[%s]", p.verifierID)
}

func (p *TaskVerifierProcessor) HealthReport() map[string]error {
	report := make(map[string]error)
	report[p.Name()] = p.Ready()
	return report
}

var (
	_ services.Service        = (*TaskVerifierProcessor)(nil)
	_ protocol.HealthReporter = (*TaskVerifierProcessor)(nil)
)
