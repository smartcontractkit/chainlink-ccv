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

// DB defines the interface for message verification logic when using durable job queues.
// Unlike Verifier, it returns results directly instead of pushing them to an in-memory batcher,
// allowing the processor to durably publish results to the job queue.
type DB interface {
	// VerifyMessages performs verification of a batch of tasks.
	// Returns successfully verified results and any verification errors that occurred.
	VerifyMessages(ctx context.Context, tasks []VerificationTask) ([]protocol.VerifierNodeResult, []VerificationError)
}

// TaskVerifierProcessorDB is a durable queue-based version of TaskVerifierProcessor.
// It replaces the in-memory batcher (SourceReaderFanout + storageBatcher) with
// PostgreSQL-backed job queues for both input (task queue) and output (result queue).
//
// One goroutine per source chain polls its dedicated task queue and runs verification,
// mirroring the per-chain concurrency model of TaskVerifierProcessor.
type TaskVerifierProcessorDB struct {
	services.StateMachine
	wg     sync.WaitGroup
	cancel context.CancelFunc

	lggr       logger.Logger
	verifierID string
	monitoring Monitoring
	verifier   DB

	// Pending writing tracker (shared with SRS and SWP)
	writingTracker *PendingWritingTracker

	// Consumes from: one task queue per source chain
	taskQueues map[protocol.ChainSelector]jobqueue.JobQueue[VerificationTask]
	// Produces to: shared result queue consumed by StorageWriterProcessorDB
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Configuration
	pollInterval    time.Duration
	cleanupInterval time.Duration
	retentionPeriod time.Duration
	batchSize       int
}

const (
	// defaultVerifierBatchSize is the maximum number of verification tasks consumed per poll.
	defaultVerifierBatchSize = 20
)

func NewTaskVerifierProcessorDB(
	lggr logger.Logger,
	verifierID string,
	verifier DB,
	monitoring Monitoring,
	taskQueues map[protocol.ChainSelector]jobqueue.JobQueue[VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	writingTracker *PendingWritingTracker,
) (*TaskVerifierProcessorDB, error) {
	p := &TaskVerifierProcessorDB{
		lggr:            lggr,
		verifierID:      verifierID,
		monitoring:      monitoring,
		verifier:        verifier,
		taskQueues:      taskQueues,
		resultQueue:     resultQueue,
		writingTracker:  writingTracker,
		pollInterval:    defaultPollInterval,
		cleanupInterval: defaultCleanupInterval,
		retentionPeriod: defaultRetentionPeriod,
		batchSize:       defaultVerifierBatchSize,
	}
	return p, nil
}

func (p *TaskVerifierProcessorDB) Start(ctx context.Context) error {
	return p.StartOnce(p.Name(), func() error {
		cancelCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		for chainSelector, taskQueue := range p.taskQueues {
			p.wg.Go(func() {
				p.run(cancelCtx, chainSelector, taskQueue)
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

func (p *TaskVerifierProcessorDB) run(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	taskQueue jobqueue.JobQueue[VerificationTask],
) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(p.cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.lggr.Infow("TaskVerifierProcessorDB context cancelled, shutting down",
				"chainSelector", chainSelector)
			return

		case <-ticker.C:
			if err := p.processBatch(ctx, chainSelector, taskQueue); err != nil {
				p.lggr.Errorw("Error processing task batch",
					"error", err,
					"chainSelector", chainSelector)
			}

		case <-cleanupTicker.C:
			if err := p.cleanup(ctx, taskQueue); err != nil {
				p.lggr.Errorw("Error running task queue cleanup",
					"error", err,
					"chainSelector", chainSelector)
			}
		}
	}
}

// processBatch consumes a batch of verification tasks from the queue, runs verification,
// publishes results to the result queue, and routes errors to retry or fail.
func (p *TaskVerifierProcessorDB) processBatch(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	taskQueue jobqueue.JobQueue[VerificationTask],
) error {
	jobs, err := taskQueue.Consume(ctx, p.batchSize)
	if err != nil {
		return fmt.Errorf("failed to consume from task queue: %w", err)
	}

	if len(jobs) == 0 {
		return nil
	}

	p.lggr.Debugw("Processing verification task batch",
		"batchSize", len(jobs),
		"chainSelector", chainSelector,
	)

	// Extract tasks and build messageID -> jobID map
	tasks := make([]VerificationTask, len(jobs))
	jobIDMap := make(map[string]string)
	for i, job := range jobs {
		tasks[i] = job.Payload
		jobIDMap[job.Payload.MessageID] = job.ID
	}

	// Metrics: finality wait duration
	for _, task := range tasks {
		if !task.QueuedAt.IsZero() && p.monitoring != nil {
			p.monitoring.Metrics().
				With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", p.verifierID).
				RecordFinalityWaitDuration(ctx, time.Since(task.QueuedAt))
		}
	}

	// Run verification — results and errors are returned directly
	results, verificationErrors := p.verifier.VerifyMessages(ctx, tasks)

	// Publish successful results to the result queue
	if len(results) > 0 {
		if err := p.resultQueue.Publish(ctx, results...); err != nil {
			return fmt.Errorf("failed to publish verification results to result queue: %w", err)
		}
	}

	// Mark successfully verified jobs as completed in the task queue
	if len(verificationErrors) < len(jobs) {
		if err := p.completeSuccessfulJobs(ctx, taskQueue, jobs, verificationErrors); err != nil {
			p.lggr.Errorw("Failed to complete successful jobs",
				"error", err,
				"chainSelector", chainSelector,
			)
		}
	}

	if len(verificationErrors) > 0 {
		p.handleVerificationErrors(ctx, chainSelector, taskQueue, verificationErrors, jobIDMap)
	} else {
		p.lggr.Debugw("Verification batch completed successfully",
			"chainSelector", chainSelector,
			"totalTasks", len(tasks),
		)
	}

	return nil
}

// completeSuccessfulJobs marks jobs that did not appear in the error list as completed.
func (p *TaskVerifierProcessorDB) completeSuccessfulJobs(
	ctx context.Context,
	taskQueue jobqueue.JobQueue[VerificationTask],
	jobs []jobqueue.Job[VerificationTask],
	verificationErrors []VerificationError,
) error {
	failedIDs := make(map[string]struct{}, len(verificationErrors))
	for _, ve := range verificationErrors {
		failedIDs[ve.Task.MessageID] = struct{}{}
	}

	successIDs := make([]string, 0, len(jobs)-len(verificationErrors))
	for _, job := range jobs {
		if _, failed := failedIDs[job.Payload.MessageID]; !failed {
			successIDs = append(successIDs, job.ID)
		}
	}

	if len(successIDs) == 0 {
		return nil
	}

	return taskQueue.Complete(ctx, successIDs...)
}

// handleVerificationErrors schedules retries or permanently fails jobs based on the error type.
func (p *TaskVerifierProcessorDB) handleVerificationErrors(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	taskQueue jobqueue.JobQueue[VerificationTask],
	verificationErrors []VerificationError,
	jobIDMap map[string]string,
) {
	p.lggr.Infow("Verification batch completed with errors",
		"chainSelector", chainSelector,
		"errorCount", len(verificationErrors))

	retryIDs := make([]string, 0)
	retryErrors := make(map[string]error)
	retryDelay := time.Duration(0)

	failIDs := make([]string, 0)
	failErrors := make(map[string]error)

	for _, ve := range verificationErrors {
		message := ve.Task.Message
		jobID, ok := jobIDMap[ve.Task.MessageID]
		if !ok {
			p.lggr.Warnw("Job ID not found for failed task", "messageID", ve.Task.MessageID)
			continue
		}

		p.monitoring.Metrics().
			With(
				"source_chain", message.SourceChainSelector.String(),
				"dest_chain", message.DestChainSelector.String(),
				"verifier_id", p.verifierID,
			).
			IncrementMessagesVerificationFailed(ctx)

		p.lggr.Errorw("Message verification failed",
			"error", ve.Error,
			"messageID", ve.Task.MessageID,
			"nonce", message.SequenceNumber,
			"sourceChain", message.SourceChainSelector,
			"destChain", message.DestChainSelector,
			"timestamp", ve.Timestamp,
			"chainSelector", chainSelector,
			"retryable", ve.Retryable,
		)

		if ve.Retryable {
			retryIDs = append(retryIDs, jobID)
			retryErrors[jobID] = ve.Error
			// Use the longest requested delay across the batch
			if d := ve.DelayOrDefault(); d > retryDelay {
				retryDelay = d
			}
		} else {
			failIDs = append(failIDs, jobID)
			failErrors[jobID] = ve.Error
			// Permanent failure — remove from tracker
			p.writingTracker.Remove(chainSelector, ve.Task.MessageID)
		}
	}

	if len(retryIDs) > 0 {
		if err := taskQueue.Retry(ctx, retryDelay, retryErrors, retryIDs...); err != nil {
			p.lggr.Errorw("Failed to schedule task retry",
				"error", err,
				"count", len(retryIDs),
				"chainSelector", chainSelector,
			)
		}
	}

	if len(failIDs) > 0 {
		if err := taskQueue.Fail(ctx, failErrors, failIDs...); err != nil {
			p.lggr.Errorw("Failed to mark tasks as permanently failed",
				"error", err,
				"count", len(failIDs),
				"chainSelector", chainSelector,
			)
		}
	}
}

func (p *TaskVerifierProcessorDB) cleanup(ctx context.Context, taskQueue jobqueue.JobQueue[VerificationTask]) error {
	deleted, err := taskQueue.Cleanup(ctx, p.retentionPeriod)
	if err != nil {
		return fmt.Errorf("failed to cleanup task queue: %w", err)
	}

	if deleted > 0 {
		p.lggr.Infow("Cleaned up archived tasks",
			"count", deleted,
			"retentionPeriod", p.retentionPeriod,
		)
	}

	return nil
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
