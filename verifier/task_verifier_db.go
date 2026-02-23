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
)

// TaskVerifierProcessorDB is a durable queue-based version of TaskVerifierProcessor.
// Instead of reading from batcher channels and writing to batcher channels, it reads from
// a VerificationTask queue and writes verification results directly to a VerifierNodeResult queue.
type TaskVerifierProcessorDB struct {
	services.StateMachine
	wg sync.WaitGroup

	lggr       logger.Logger
	verifierID string
	monitoring Monitoring
	verifier   Verifier

	// Pending writing tracker (shared with SRS and SWP)
	writingTracker *PendingWritingTracker

	// Consumes from verification_tasks queue
	taskQueue jobqueue.JobQueue[VerificationTask]
	// Produces to verification_results queue
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Configuration
	pollInterval time.Duration
	batchSize    int
}

func NewTaskVerifierProcessorDB(
	lggr logger.Logger,
	verifierID string,
	verifier Verifier,
	monitoring Monitoring,
	taskQueue jobqueue.JobQueue[VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	writingTracker *PendingWritingTracker,
	batchSize int,
) (*TaskVerifierProcessorDB, error) {
	p := &TaskVerifierProcessorDB{
		lggr:           lggr,
		verifierID:     verifierID,
		monitoring:     monitoring,
		verifier:       verifier,
		taskQueue:      taskQueue,
		resultQueue:    resultQueue,
		writingTracker: writingTracker,
		pollInterval:   defaultTaskPollInterval,
		batchSize:      batchSize,
	}
	return p, nil
}

func (p *TaskVerifierProcessorDB) Start(ctx context.Context) error {
	return p.StartOnce(p.Name(), func() error {
		p.wg.Go(func() {
			p.run(ctx)
		})
		return nil
	})
}

func (p *TaskVerifierProcessorDB) Close() error {
	return p.StopOnce(p.Name(), func() error {
		p.wg.Wait()
		return nil
	})
}

func (p *TaskVerifierProcessorDB) run(ctx context.Context) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.lggr.Infow("TaskVerifierProcessorDB context cancelled, shutting down")
			return

		case <-ticker.C:
			if err := p.processBatch(ctx); err != nil {
				p.lggr.Errorw("Error processing verification batch", "error", err)
			}
		}
	}
}

func (p *TaskVerifierProcessorDB) processBatch(ctx context.Context) error {
	// Consume batch of tasks from queue
	jobs, err := p.taskQueue.Consume(ctx, p.batchSize)
	if err != nil {
		return fmt.Errorf("failed to consume from task queue: %w", err)
	}

	if len(jobs) == 0 {
		return nil // No work to do
	}

	p.lggr.Debugw("Processing verification tasks batch",
		"batchSize", len(jobs),
	)

	// Extract tasks and build job ID map
	tasks := make([]VerificationTask, len(jobs))
	jobIDMap := make(map[string]string) // messageID -> jobID
	for i, job := range jobs {
		tasks[i] = job.Payload
		jobIDMap[job.Payload.MessageID] = job.ID
	}

	// Track finality wait duration metrics
	for _, task := range tasks {
		if !task.QueuedAt.IsZero() && p.monitoring != nil {
			finalityWaitDuration := time.Since(task.QueuedAt)
			p.monitoring.Metrics().
				With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", p.verifierID).
				RecordFinalityWaitDuration(ctx, finalityWaitDuration)
		}
	}

	// Verify messages
	results := p.verifier.VerifyMessages(ctx, tasks)

	// Process verification results
	return p.handleVerificationResults(ctx, results, jobIDMap)
}

// handleVerificationResults processes verification results, updating job statuses and publishing successful results.
func (p *TaskVerifierProcessorDB) handleVerificationResults(
	ctx context.Context,
	results []VerificationResult,
	jobIDMap map[string]string,
) error {
	if len(results) == 0 {
		return nil
	}

	var successCount, errorCount int
	successfulResults := make([]protocol.VerifierNodeResult, 0)
	completedJobIDs := make([]string, 0)
	retryJobIDs := make([]string, 0)
	retryErrors := make(map[string]error)
	failedJobIDs := make([]string, 0)
	failedErrors := make(map[string]error)

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
			p.handleVerificationError(ctx, *result.Error, jobID, &retryJobIDs, retryErrors, &failedJobIDs, failedErrors)
		} else if result.Result != nil {
			successCount++
			successfulResults = append(successfulResults, *result.Result)
			completedJobIDs = append(completedJobIDs, jobID)
		}
	}

	// Publish successful results to verification_results queue
	if len(successfulResults) > 0 {
		publishCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := p.resultQueue.Publish(publishCtx, successfulResults...); err != nil {
			p.lggr.Errorw("Failed to publish verification results to queue",
				"error", err,
				"count", len(successfulResults))
			// Results are lost - consider retrying the entire batch
			// For now, we'll retry the jobs to re-verify
			for _, jobID := range completedJobIDs {
				retryJobIDs = append(retryJobIDs, jobID)
				retryErrors[jobID] = err
			}
			completedJobIDs = nil
		} else {
			p.lggr.Debugw("Published verification results to queue", "count", len(successfulResults))
		}
	}

	// Complete successfully processed jobs
	if len(completedJobIDs) > 0 {
		if err := p.taskQueue.Complete(ctx, completedJobIDs...); err != nil {
			p.lggr.Errorw("Failed to complete jobs in queue",
				"error", err,
				"count", len(completedJobIDs))
		}
	}

	// Retry jobs with retryable errors
	if len(retryJobIDs) > 0 {
		if err := p.taskQueue.Retry(ctx, 10*time.Second, retryErrors, retryJobIDs...); err != nil {
			p.lggr.Errorw("Failed to retry jobs",
				"error", err,
				"count", len(retryJobIDs))
		}
	}

	// Fail jobs with permanent errors
	if len(failedJobIDs) > 0 {
		if err := p.taskQueue.Fail(ctx, failedErrors, failedJobIDs...); err != nil {
			p.lggr.Errorw("Failed to mark jobs as failed",
				"error", err,
				"count", len(failedJobIDs))
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
func (p *TaskVerifierProcessorDB) handleVerificationError(
	ctx context.Context,
	verificationError VerificationError,
	jobID string,
	retryJobIDs *[]string,
	retryErrors map[string]error,
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
	} else {
		*failedJobIDs = append(*failedJobIDs, jobID)
		failedErrors[jobID] = verificationError.Error
		// Remove from pending tracker for permanent failures
		p.writingTracker.Remove(
			message.SourceChainSelector,
			verificationError.Task.MessageID,
		)
	}
}

func (p *TaskVerifierProcessorDB) Name() string {
	return fmt.Sprintf("verifier.TaskVerifierProcessorDB[%s]", p.verifierID)
}

func (p *TaskVerifierProcessorDB) HealthReport() map[string]error {
	report := make(map[string]error)
	report[p.Name()] = p.Ready()
	return report
}

var (
	_ services.Service        = (*TaskVerifierProcessorDB)(nil)
	_ protocol.HealthReporter = (*TaskVerifierProcessorDB)(nil)
)
