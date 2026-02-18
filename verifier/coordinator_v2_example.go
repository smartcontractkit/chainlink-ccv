package verifier

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// CoordinatorDBExample demonstrates how to wire up the DB processors with durable queues.
// This is an example showing the migration path from the current batcher-based approach.

// SetupDurableQueues creates and initializes the job queues
func SetupDurableQueues(
	ctx context.Context,
	db *sql.DB,
	lggr logger.Logger,
) (jobqueue.JobQueue[VerificationTask], jobqueue.JobQueue[protocol.VerifierNodeResult], error) {
	// Create verification tasks queue
	taskQueueConfig := jobqueue.QueueConfig{
		Name:                "verification_tasks",
		DefaultMaxAttempts:  5,
		DefaultLockDuration: 5 * time.Minute,
		DefaultBatchSize:    20,
		PollInterval:        100 * time.Millisecond,
		RetentionPeriod:     7 * 24 * time.Hour,
	}

	taskQueue, err := jobqueue.NewPostgresJobQueue[VerificationTask](
		db,
		taskQueueConfig,
		logger.With(lggr, "component", "task_queue"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create task queue: %w", err)
	}

	// Create verification results queue
	resultQueueConfig := jobqueue.QueueConfig{
		Name:                "verification_results",
		DefaultMaxAttempts:  5,
		DefaultLockDuration: 5 * time.Minute,
		DefaultBatchSize:    50,
		PollInterval:        100 * time.Millisecond,
		RetentionPeriod:     7 * 24 * time.Hour,
	}

	resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
		db,
		resultQueueConfig,
		logger.With(lggr, "component", "result_queue"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create result queue: %w", err)
	}

	return taskQueue, resultQueue, nil
}

// Example: Migration Step 1 - StorageWriterProcessor Only
// This shows how to replace just the StorageWriterProcessor while keeping
// other components unchanged (dual-write approach)
func ExampleMigrationStep1_StorageWriter(
	ctx context.Context,
	db *sql.DB,
	lggr logger.Logger,
	config CoordinatorConfig,
	storage protocol.CCVNodeDataWriter,
	messageTracker MessageLatencyTracker,
	chainStatusManager protocol.ChainStatusManager,
) error {
	// Create result queue only
	_, resultQueue, err := SetupDurableQueues(ctx, db, lggr)
	if err != nil {
		return err
	}

	// Create DB StorageWriterProcessor
	writingTracker := NewPendingWritingTracker(lggr)
	swp, err := NewStorageWriterProcessorDB(
		ctx,
		lggr,
		config.VerifierID,
		messageTracker,
		storage,
		resultQueue, // Uses queue
		config,
		writingTracker,
		chainStatusManager,
	)
	if err != nil {
		return fmt.Errorf("failed to create StorageWriterProcessorDB: %w", err)
	}

	// Start processor
	if err := swp.Start(ctx); err != nil {
		return fmt.Errorf("failed to start StorageWriterProcessorDB: %w", err)
	}

	// NOTE: TaskVerifierProcessor (V1) needs to be modified to publish
	// to resultQueue in addition to the batcher for dual-write testing

	lggr.Infow("StorageWriterProcessorDB started", "verifier_id", config.VerifierID)
	return nil
}

// Example: Migration Step 2 - Full DB Pipeline
// This shows the complete setup with all DB processors
func ExampleMigrationStep2_FullPipeline(
	ctx context.Context,
	db *sql.DB,
	lggr logger.Logger,
	config CoordinatorConfig,
	verifier Verifier,
	monitoring Monitoring,
	storage protocol.CCVNodeDataWriter,
	messageTracker MessageLatencyTracker,
	chainStatusManager protocol.ChainStatusManager,
) (
	jobqueue.JobQueue[VerificationTask],
	jobqueue.JobQueue[protocol.VerifierNodeResult],
	*TaskVerifierProcessorDB,
	*StorageWriterProcessorDB,
	error,
) {
	// 1. Setup queues
	taskQueue, resultQueue, err := SetupDurableQueues(ctx, db, lggr)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// 2. Create shared writing tracker
	writingTracker := NewPendingWritingTracker(lggr)

	// 3. Create StorageWriterProcessorDB
	var swp *StorageWriterProcessorDB
	swp, err = NewStorageWriterProcessorDB(
		ctx,
		logger.With(lggr, "component", "storage_writer"),
		config.VerifierID,
		messageTracker,
		storage,
		resultQueue,
		config,
		writingTracker,
		chainStatusManager,
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create StorageWriterProcessorDB: %w", err)
	}

	// 4. Create TaskVerifierProcessorDB
	chainSelectors := make([]protocol.ChainSelector, 0, len(config.SourceConfigs))
	for cs := range config.SourceConfigs {
		chainSelectors = append(chainSelectors, cs)
	}

	var tvp *TaskVerifierProcessorDB
	tvp, err = NewTaskVerifierProcessorDB(
		logger.With(lggr, "component", "task_verifier"),
		config.VerifierID,
		verifier,
		monitoring,
		taskQueue,
		resultQueue,
		writingTracker,
		chainSelectors,
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create TaskVerifierProcessorDB: %w", err)
	}

	// 5. Start processors
	if err := swp.Start(ctx); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to start StorageWriterProcessorDB: %w", err)
	}

	if err := tvp.Start(ctx); err != nil {
		swp.Close() // cleanup
		return nil, nil, nil, nil, fmt.Errorf("failed to start TaskVerifierProcessorDB: %w", err)
	}

	lggr.Infow("DB pipeline started successfully",
		"verifier_id", config.VerifierID,
		"chains", len(chainSelectors),
	)

	// NOTE: SourceReaderService still needs to be updated to publish to taskQueue
	// instead of using batcher

	return taskQueue, resultQueue, tvp, swp, nil
}

// Example: How to update SourceReaderService to publish to queue
func ExampleSourceReaderPublishToQueue(
	ctx context.Context,
	taskQueue jobqueue.JobQueue[VerificationTask],
	tasks []VerificationTask,
	lggr logger.Logger,
) error {
	if len(tasks) == 0 {
		return nil
	}

	// Publish tasks to durable queue
	if err := taskQueue.Publish(ctx, tasks...); err != nil {
		return fmt.Errorf("failed to publish tasks to queue: %w", err)
	}

	lggr.Debugw("Published tasks to queue",
		"count", len(tasks),
		"chain", tasks[0].Message.SourceChainSelector,
	)

	return nil
}

// Example: Queue monitoring and health checks
func ExampleQueueHealthCheck(
	ctx context.Context,
	taskQueue jobqueue.JobQueue[VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	lggr logger.Logger,
) error {
	// Simple health check - try to consume (with limit 0 to avoid actually processing)
	// In production, you'd query the database directly for metrics

	lggr.Info("Queue health check - use SQL queries for detailed metrics")
	lggr.Info("Example: SELECT status, COUNT(*) FROM verification_tasks GROUP BY status")

	return nil
}

// Example: Graceful shutdown
func ExampleGracefulShutdown(
	ctx context.Context,
	tvp *TaskVerifierProcessorDB,
	swp *StorageWriterProcessorDB,
	taskQueue jobqueue.JobQueue[VerificationTask],
	resultQueue jobqueue.JobQueue[protocol.VerifierNodeResult],
	lggr logger.Logger,
) error {
	lggr.Infow("Starting graceful shutdown")

	// 1. Stop accepting new work (stop SRS first)
	// ... (SRS shutdown code)

	// 2. Stop TaskVerifierProcessor (will finish current batch)
	if err := tvp.Close(); err != nil {
		lggr.Errorw("Error closing TaskVerifierProcessor", "error", err)
	}

	// 3. Stop StorageWriterProcessor (will finish current batch)
	if err := swp.Close(); err != nil {
		lggr.Errorw("Error closing StorageWriterProcessor", "error", err)
	}

	// 4. Check remaining queue depth with SQL
	lggr.Infow("Shutdown complete - check queue depth with SQL queries")
	lggr.Info("Example: SELECT COUNT(*) FROM verification_tasks WHERE status = 'pending'")

	// Jobs in queue will be processed when service restarts
	return nil
}

// Example: Feature flag for gradual rollout
type ProcessorVersion string

const (
	ProcessorVersionV1 ProcessorVersion = "v1"
	ProcessorVersionV2 ProcessorVersion = "v2"
)

func SetupProcessorsWithFeatureFlag(
	ctx context.Context,
	db *sql.DB,
	version ProcessorVersion,
	// ... other params
) error {
	switch version {
	case ProcessorVersionV1:
		// Use existing batcher-based processors
		return setupV1Processors(ctx /* ... */)
	case ProcessorVersionV2:
		// Use new queue-based processors
		return setupV2Processors(ctx, db /* ... */)
	default:
		return fmt.Errorf("unknown processor version: %s", version)
	}
}

// Stub functions for example
func setupV1Processors(ctx context.Context) error             { return nil }
func setupV2Processors(ctx context.Context, db *sql.DB) error { return nil }
