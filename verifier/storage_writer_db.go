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

// StorageWriterProcessorDB is a durable queue-based version of StorageWriterProcessor.
// It replaces the in-memory batcher with a PostgreSQL-backed job queue for durability.
type StorageWriterProcessorDB struct {
	services.StateMachine
	wg sync.WaitGroup

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

func NewStorageWriterProcessorDB(
	ctx context.Context,
	lggr logger.Logger,
	verifierID string,
	messageTracker MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	config CoordinatorConfig,
	writingTracker *PendingWritingTracker,
	chainStatusManager protocol.ChainStatusManager,
) (*StorageWriterProcessorDB, error) {
	storageBatchSize, _, retryDelay := configWithDefaults(lggr, config)

	processor := &StorageWriterProcessorDB{
		lggr:               lggr,
		verifierID:         verifierID,
		messageTracker:     messageTracker,
		storage:            storage,
		resultQueue:        resultQueue,
		retryDelay:         retryDelay,
		writingTracker:     writingTracker,
		chainStatusManager: chainStatusManager,
		pollInterval:       defaultPollInterval,
		cleanupInterval:    defaultCleanupInterval,
		retentionPeriod:    defaultRetentionPeriod,
		batchSize:          storageBatchSize,
	}
	return processor, nil
}

func (s *StorageWriterProcessorDB) Start(ctx context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.run(ctx)
		})
		return nil
	})
}

func (s *StorageWriterProcessorDB) Close() error {
	return s.StopOnce(s.Name(), func() error {
		s.wg.Wait()
		return nil
	})
}

func (s *StorageWriterProcessorDB) run(ctx context.Context) {
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(s.cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.lggr.Infow("StorageWriterProcessor context cancelled, shutting down")
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

func (s *StorageWriterProcessorDB) processBatch(ctx context.Context) error {
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

	// Extract results and build job ID map
	results := make([]protocol.VerifierNodeResult, len(jobs))
	jobIDMap := make(map[string]string) // messageID -> jobID
	for i, job := range jobs {
		results[i] = job.Payload
		jobIDMap[job.Payload.MessageID.String()] = job.ID
	}

	// Write batch to storage
	if err := s.storage.WriteCCVNodeData(ctx, results); err != nil {
		s.lggr.Errorw("Failed to write CCV data batch to storage, scheduling retry",
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

	s.lggr.Infow("CCV data batch stored successfully",
		"batchSize", len(results),
	)

	// Success: complete jobs, remove from tracker, and update checkpoints
	jobIDs := make([]string, len(jobs))
	affectedChains := make(map[protocol.ChainSelector]struct{})

	for i, job := range jobs {
		jobIDs[i] = job.ID
		result := job.Payload
		chain := result.Message.SourceChainSelector
		s.writingTracker.Remove(chain, result.MessageID.String())
		affectedChains[chain] = struct{}{}
	}

	// Mark jobs as completed in queue
	if err := s.resultQueue.Complete(ctx, jobIDs...); err != nil {
		s.lggr.Errorw("Failed to complete jobs in queue",
			"error", err,
			"batchSize", len(jobIDs),
		)
		// Continue anyway - data is written, tracking will catch up
	}

	// Update checkpoints
	s.updateCheckpoints(ctx, affectedChains)

	// Track message latencies
	s.messageTracker.TrackMessageLatencies(ctx, results)

	return nil
}

func (s *StorageWriterProcessorDB) updateCheckpoints(ctx context.Context, chains map[protocol.ChainSelector]struct{}) {
	statuses := make([]protocol.ChainStatusInfo, 0, len(chains))

	for chain := range chains {
		checkpoint, shouldWrite := s.writingTracker.CheckpointIfAdvanced(chain)
		if !shouldWrite {
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

func (s *StorageWriterProcessorDB) cleanup(ctx context.Context) error {
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

func (s *StorageWriterProcessorDB) Name() string {
	return fmt.Sprintf("verifier.StorageWriterProcessorDB[%s]", s.verifierID)
}

func (s *StorageWriterProcessorDB) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()
	return report
}

var (
	_ services.Service        = (*StorageWriterProcessorDB)(nil)
	_ protocol.HealthReporter = (*StorageWriterProcessorDB)(nil)
)
