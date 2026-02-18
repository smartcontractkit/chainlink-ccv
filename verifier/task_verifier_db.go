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

// TaskVerifierProcessorDB is a durable queue-based version of TaskVerifierProcessor.
// It consumes VerificationTask jobs from a queue, verifies them, and publishes
// VerifierNodeResult jobs to another queue.
type TaskVerifierProcessorDB struct {
	services.StateMachine
	wg     sync.WaitGroup
	cancel context.CancelFunc

	lggr       logger.Logger
	verifierID string
	monitoring Monitoring
	verifier   Verifier

	// Pending writing tracker (shared with SRS and SWP)
	writingTracker *PendingWritingTracker

	// Consumes from task queue
	taskQueue jobqueue.JobQueue[VerificationTask]
	// Publishes to result queue
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Configuration
	pollInterval time.Duration
	batchSize    int
	lockDuration time.Duration

	// Per-chain goroutines
	chainSelectors []protocol.ChainSelector
}

func NewTaskVerifierProcessorDB(
	lggr logger.Logger,
	verifierID string,
	verifier Verifier,
	monitoring Monitoring,
	taskQueue jobqueue.JobQueue[VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	writingTracker *PendingWritingTracker,
	chainSelectors []protocol.ChainSelector,
) (*TaskVerifierProcessorDB, error) {
	p := &TaskVerifierProcessorDB{
		lggr:           lggr,
		verifierID:     verifierID,
		monitoring:     monitoring,
		verifier:       verifier,
		taskQueue:      taskQueue,
		resultQueue:    resultQueue,
		writingTracker: writingTracker,
		chainSelectors: chainSelectors,
		pollInterval:   100 * time.Millisecond, // configurable
		batchSize:      20,                     // configurable
		lockDuration:   5 * time.Minute,
	}
	return p, nil
}

func (p *TaskVerifierProcessorDB) Start(ctx context.Context) error {
	return p.StartOnce(p.Name(), func() error {
		cancelCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel

		// Start one goroutine per source chain for concurrent processing
		for _, chainSelector := range p.chainSelectors {
			chainSelector := chainSelector // capture loop variable
			p.wg.Go(func() {
				p.run(cancelCtx, chainSelector)
			})
		}

		return nil
	})
}

func (p *TaskVerifierProcessorDB) Close() error {
	return p.StopOnce(p.Name(), func() error {
		p.cancel()
		p.wg.Wait()
		return nil
	})
}

func (p *TaskVerifierProcessorDB) run(ctx context.Context, chainSelector protocol.ChainSelector) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	p.lggr.Infow("TaskVerifierProcessor started for chain",
		"chain", chainSelector,
	)

	for {
		select {
		case <-ctx.Done():
			p.lggr.Infow("TaskVerifierProcessor context cancelled",
				"chain", chainSelector,
			)
			return

		case <-ticker.C:
			if err := p.processBatch(ctx, chainSelector); err != nil {
				p.lggr.Errorw("Error processing verification batch",
					"chain", chainSelector,
					"error", err,
				)
			}
		}
	}
}

func (p *TaskVerifierProcessorDB) processBatch(ctx context.Context, chainSelector protocol.ChainSelector) error {
	// Consume batch of tasks from queue
	jobs, err := p.taskQueue.Consume(ctx, p.batchSize, p.lockDuration)
	if err != nil {
		return fmt.Errorf("failed to consume from task queue: %w", err)
	}

	// Filter jobs for this chain
	var chainJobs []jobqueue.Job[VerificationTask]
	for _, job := range jobs {
		if job.Payload.Message.SourceChainSelector == chainSelector {
			chainJobs = append(chainJobs, job)
		}
	}

	if len(chainJobs) == 0 {
		return nil // No work for this chain
	}

	p.lggr.Debugw("Processing verification tasks batch",
		"chain", chainSelector,
		"batchSize", len(chainJobs),
	)

	// Extract tasks and build job ID map
	tasks := make([]VerificationTask, len(chainJobs))
	jobIDMap := make(map[string]string) // messageID -> jobID
	for i, job := range chainJobs {
		tasks[i] = job.Payload
		jobIDMap[job.Payload.MessageID] = job.ID
	}

	// Record finality wait duration metrics
	for _, task := range tasks {
		if !task.QueuedAt.IsZero() && p.monitoring != nil {
			finalityWaitDuration := time.Since(task.QueuedAt)
			p.monitoring.Metrics().
				With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", p.verifierID).
				RecordFinalityWaitDuration(ctx, finalityWaitDuration)
		}
	}

	// Verify messages - this publishes successful results directly to resultQueue
	errorBatch := p.verifier.VerifyMessages(ctx, tasks, p.resultQueue)

	// Handle verification results
	return p.handleVerificationResults(ctx, chainSelector, chainJobs, errorBatch, jobIDMap)
}

func (p *TaskVerifierProcessorDB) handleVerificationResults(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	jobs []jobqueue.Job[VerificationTask],
	errorBatch []VerificationError,
	jobIDMap map[string]string,
) error {
	// Build error map by job ID
	errorsByJobID := make(map[string]VerificationError)
	for _, verr := range errorBatch {
		if jobID, ok := jobIDMap[verr.Task.MessageID]; ok {
			errorsByJobID[jobID] = verr
		}
	}

	// Separate jobs into: completed, retry, failed
	var completedIDs []string
	retryErrors := make(map[string]error)
	var retryIDs []string
	failErrors := make(map[string]error)
	var failIDs []string

	for _, job := range jobs {
		jobID := job.ID
		verr, hasError := errorsByJobID[jobID]

		if !hasError {
			// Success - task was verified and result published
			completedIDs = append(completedIDs, jobID)
			continue
		}

		// Log error
		message := verr.Task.Message
		p.monitoring.Metrics().
			With(
				"source_chain", message.SourceChainSelector.String(),
				"dest_chain", message.DestChainSelector.String(),
				"verifier_id", p.verifierID,
			).
			IncrementMessagesVerificationFailed(ctx)

		p.lggr.Errorw("Message verification failed",
			"error", verr.Error,
			"messageID", verr.Task.MessageID,
			"nonce", message.SequenceNumber,
			"sourceChain", message.SourceChainSelector,
			"destChain", message.DestChainSelector,
			"timestamp", verr.Timestamp,
			"chainSelector", chainSelector,
			"retryable", verr.Retryable,
			"attempts", job.AttemptCount,
		)

		if verr.Retryable {
			retryIDs = append(retryIDs, jobID)
			retryErrors[jobID] = verr.Error
		} else {
			// Permanent failure
			failIDs = append(failIDs, jobID)
			failErrors[jobID] = verr.Error

			// Remove from tracker
			p.writingTracker.Remove(chainSelector, verr.Task.MessageID)
		}
	}

	// Complete successful jobs
	if len(completedIDs) > 0 {
		if err := p.taskQueue.Complete(ctx, completedIDs...); err != nil {
			p.lggr.Errorw("Failed to complete tasks in queue",
				"error", err,
				"count", len(completedIDs),
			)
		}
	}

	// Retry failed but retryable jobs
	if len(retryIDs) > 0 {
		// Use exponential backoff based on attempt count
		delay := 2 * time.Second
		if len(jobs) > 0 && jobs[0].AttemptCount > 1 {
			delay = time.Duration(1<<uint(jobs[0].AttemptCount-1)) * time.Second
			if delay > 5*time.Minute {
				delay = 5 * time.Minute
			}
		}

		if err := p.taskQueue.Retry(ctx, delay, retryErrors, retryIDs...); err != nil {
			p.lggr.Errorw("Failed to retry tasks in queue",
				"error", err,
				"count", len(retryIDs),
			)
		}
	}

	// Fail permanently failed jobs
	if len(failIDs) > 0 {
		if err := p.taskQueue.Fail(ctx, failErrors, failIDs...); err != nil {
			p.lggr.Errorw("Failed to mark tasks as failed in queue",
				"error", err,
				"count", len(failIDs),
			)
		}
	}

	p.lggr.Debugw("Verification batch completed",
		"chain", chainSelector,
		"total", len(jobs),
		"completed", len(completedIDs),
		"retry", len(retryIDs),
		"failed", len(failIDs),
	)

	return nil
}

func (p *TaskVerifierProcessorDB) Name() string {
	return fmt.Sprintf("verifier.TaskVerifierProcessorDB[%s]", p.verifierID)
}

func (p *TaskVerifierProcessorDB) HealthReport() map[string]error {
	report := make(map[string]error)
	report[p.Name()] = p.Ready()

	// Simple health check - verify we can query queues
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check task queue health
	_, err := p.taskQueue.Consume(ctx, 1, 1*time.Second)
	if err != nil {
		report[p.Name()+" task_queue"] = fmt.Errorf("task queue health check failed: %w", err)
	}

	return report
}

var (
	_ services.Service        = (*TaskVerifierProcessorDB)(nil)
	_ protocol.HealthReporter = (*TaskVerifierProcessorDB)(nil)
)
