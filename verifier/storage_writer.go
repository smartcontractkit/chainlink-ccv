package verifier

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
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

// StorageWriterProcessor handles batching and writing CCVNodeData to the offchain storage.
// It represents the final stage (3rd step) in the verifier processing pipeline.
//
// We assume here that all failures are transient and can be retried. (e.g. network issues).
// Therefore, on failure, we schedule a retry after a configured retryDelay.
type StorageWriterProcessor struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	lggr           logger.Logger
	verifierID     string
	messageTracker MessageLatencyTracker

	storage     protocol.CCVNodeDataWriter
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult]

	// Pending writing tracker (shared with SRS and TVP)
	writingTracker *PendingWritingTracker

	// ChainStatus management for checkpoint writing
	chainStatusManager protocol.ChainStatusManager

	// Configuration
	pollInterval    time.Duration
	cleanupInterval time.Duration
	retentionPeriod time.Duration
	batchSize       int
	retryDelay      time.Duration
}

func NewStorageWriterProcessor(
	ctx context.Context,
	lggr logger.Logger,
	verifierID string,
	messageTracker MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config CoordinatorConfig,
	writingTracker *PendingWritingTracker,
	chainStatusManager protocol.ChainStatusManager,
) (*StorageWriterProcessor, error) {
	return NewStorageWriterProcessorWithPollInterval(
		ctx, lggr, verifierID, messageTracker, storage, resultQueue, config, writingTracker, chainStatusManager, defaultPollInterval,
	)
}

func NewStorageWriterProcessorWithPollInterval(
	ctx context.Context,
	lggr logger.Logger,
	verifierID string,
	messageTracker MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config CoordinatorConfig,
	writingTracker *PendingWritingTracker,
	chainStatusManager protocol.ChainStatusManager,
	pollInterval time.Duration,
) (*StorageWriterProcessor, error) {
	storageBatchSize, _, retryDelay := configWithDefaults(lggr, config)

	processor := &StorageWriterProcessor{
		lggr:               lggr,
		verifierID:         verifierID,
		messageTracker:     messageTracker,
		storage:            storage,
		resultQueue:        resultQueue,
		retryDelay:         retryDelay,
		writingTracker:     writingTracker,
		chainStatusManager: chainStatusManager,
		pollInterval:       pollInterval,
		cleanupInterval:    defaultCleanupInterval,
		retentionPeriod:    defaultRetentionPeriod,
		batchSize:          storageBatchSize,
		stopCh:             make(chan struct{}),
	}
	return processor, nil
}

func (s *StorageWriterProcessor) Start(context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.run()
		})
		return nil
	})
}

func (s *StorageWriterProcessor) Close() error {
	return s.StopOnce(s.Name(), func() error {
		close(s.stopCh)
		s.wg.Wait()
		return nil
	})
}

func (s *StorageWriterProcessor) run() {
	ctx, cancel := s.stopCh.NewCtx()
	defer cancel()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(s.cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.lggr.Infow("StorageWriterProcessor close signal received, shutting down")
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

func (s *StorageWriterProcessor) processBatch(ctx context.Context) error {
	// Consume batch of results from queue
	jobs, err := s.resultQueue.Consume(ctx, s.batchSize)
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

		if retryErr := s.resultQueue.Retry(ctx, s.retryDelay, errorMap, jobIDs...); retryErr != nil {
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

		if retryErr := s.resultQueue.Retry(ctx, s.retryDelay, failedErrorMap, retriableFailedJobs...); retryErr != nil {
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

		if failErr := s.resultQueue.Fail(ctx, failedErrorMap, nonRetriableFailedJobs...); failErr != nil {
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

	// Success: complete jobs, remove from tracker, and update checkpoints
	affectedChains := make(map[protocol.ChainSelector]struct{})

	for i := range successfulJobs {
		result := successfulResults[i]
		chain := result.Message.SourceChainSelector
		s.writingTracker.Remove(chain, result.MessageID.String())
		affectedChains[chain] = struct{}{}
	}

	// Mark successful jobs as completed in queue
	if err := s.resultQueue.Complete(ctx, successfulJobs...); err != nil {
		s.lggr.Errorw("Failed to complete jobs in queue",
			"error", err,
			"successfulCount", len(successfulJobs),
		)
		// Continue anyway - data is written, tracking will catch up
	}

	// Update checkpoints
	s.updateCheckpoints(ctx, affectedChains)

	// Track message latencies
	s.messageTracker.TrackMessageLatencies(ctx, successfulResults)

	return nil
}

func (s *StorageWriterProcessor) updateCheckpoints(ctx context.Context, chains map[protocol.ChainSelector]struct{}) {
	statuses := make([]protocol.ChainStatusInfo, 0, len(chains))

	for chain := range chains {
		checkpoint, shouldWrite := s.writingTracker.CheckpointIfAdvanced(chain)
		if !shouldWrite {
			continue
		}

		// Do not advance checkpoints for disabled chains; avoid implicit re-enable after violations.
		stMap, err := s.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{chain})
		if err != nil {
			s.lggr.Errorw("Failed to read chain status, skipping checkpoint update", "chain", chain, "error", err)
			continue
		}
		if st, ok := stMap[chain]; ok && st.Disabled {
			s.lggr.Infow("Skipping checkpoint update: chain disabled", "chain", chain)
			continue
		}

		// Safely convert uint64 to *big.Int to avoid overflow issues
		checkpointBig := new(big.Int).SetUint64(checkpoint)

		statuses = append(statuses, protocol.ChainStatusInfo{
			ChainSelector:        chain,
			FinalizedBlockHeight: checkpointBig,
		})

		s.lggr.Infow("Checkpoint advanced",
			"chain", chain,
			"checkpoint", checkpoint)
	}

	if len(statuses) > 0 {
		if err := s.chainStatusManager.WriteChainStatuses(ctx, statuses); err != nil {
			s.lggr.Errorw("Failed to write checkpoint", "error", err)
		}
	}
}

func (s *StorageWriterProcessor) cleanup(ctx context.Context) error {
	// Cleanup archived jobs older than retention period
	deleted, err := s.resultQueue.Cleanup(ctx, s.retentionPeriod)
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

func (s *StorageWriterProcessor) Name() string {
	return fmt.Sprintf("verifier.StorageWriterProcessor[%s]", s.verifierID)
}

func (s *StorageWriterProcessor) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()
	return report
}

func configWithDefaults(lggr logger.Logger, config CoordinatorConfig) (int, time.Duration, time.Duration) {
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
	_ services.Service        = (*StorageWriterProcessor)(nil)
	_ protocol.HealthReporter = (*StorageWriterProcessor)(nil)
)
