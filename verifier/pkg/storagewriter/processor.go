package storagewriter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// defaultPollInterval is how frequently the storage writer polls for new jobs.
	defaultPollInterval = 500 * time.Millisecond
	// defaultCleanupInterval is how frequently the storage writer cleans up archived jobs.
	defaultCleanupInterval = 4 * time.Hour
	// defaultRetentionPeriod is how long archived jobs are kept before deletion.
	defaultRetentionPeriod = 30 * 24 * time.Hour // 30 days
)

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
	messageTracker verifier.MessageLatencyTracker

	storage     protocol.CCVNodeDataWriter
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Configuration
	pollInterval    time.Duration
	cleanupInterval time.Duration
	retentionPeriod time.Duration
	batchSize       int
	retryDelay      time.Duration
}

func NewProcessor(
	lggr logger.Logger,
	verifierID string,
	messageTracker verifier.MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config verifier.CoordinatorConfig,
) (*Processor, error) {
	return NewProcessorWithPollInterval(
		lggr, verifierID, messageTracker, storage, resultQueue, config, defaultPollInterval,
	)
}

func NewProcessorWithPollInterval(
	lggr logger.Logger,
	verifierID string,
	messageTracker verifier.MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config verifier.CoordinatorConfig,
	pollInterval time.Duration,
) (*Processor, error) {
	storageBatchSize, _, retryDelay := configWithDefaults(lggr, config)

	processor := &Processor{
		lggr:            lggr,
		verifierID:      verifierID,
		messageTracker:  messageTracker,
		storage:         storage,
		resultQueue:     resultQueue,
		retryDelay:      retryDelay,
		pollInterval:    pollInterval,
		cleanupInterval: defaultCleanupInterval,
		retentionPeriod: defaultRetentionPeriod,
		batchSize:       storageBatchSize,
		stopCh:          make(chan struct{}),
	}
	return processor, nil
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

func (s *Processor) processBatch(ctx context.Context) error {
	// Consume batch of results from queue
	consumeCtx, cancel := context.WithTimeout(ctx, verifier.DefaultJobQueueOperationTimeout)
	defer cancel()

	jobs, err := s.resultQueue.Consume(consumeCtx, s.batchSize)
	if err != nil {
		return fmt.Errorf("failed to consume from result queue: %w", err)
	}

	if len(jobs) == 0 {
		return nil // No work to do
	}

	s.lggr.Debugw("Processing verification results batch",
		"batchSize", len(jobs),
	)

	// Extract results for writing
	results := make([]protocol.VerifierNodeResult, len(jobs))
	for i, job := range jobs {
		results[i] = job.Payload
	}

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

		if writeResult.Status == protocol.WriteSuccess {
			successfulJobs = append(successfulJobs, jobID)
			successfulResults = append(successfulResults, writeResult.Input)
			s.lggr.Debugw("Write succeeded for message", "messageID", messageID, "jobID", jobID)
		} else {
			if writeResult.Retryable {
				retriableFailedJobs = append(retriableFailedJobs, jobID)
				failedErrorMap[jobID] = writeResult.Error
				s.lggr.Errorw("Write failed for message (retryable)",
					"messageID", messageID,
					"jobID", jobID,
					"error", writeResult.Error,
				)
			} else {
				nonRetriableFailedJobs = append(nonRetriableFailedJobs, jobID)
				failedErrorMap[jobID] = writeResult.Error
				s.lggr.Errorw("Write failed for message (non-retryable)",
					"messageID", messageID,
					"jobID", jobID,
					"error", writeResult.Error,
				)
			}
		}
	}

	// Log summary
	s.lggr.Infow("CCV data batch write completed",
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
