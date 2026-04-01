package replay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Storage is the subset of storage operations the replay engine needs.
type Storage interface {
	// UpsertVerifierResults inserts or overwrites verifier results based on force flag.
	UpsertVerifierResults(ctx context.Context, results []common.VerifierResultWithMetadata, force bool) error
	// UpsertMessages inserts or overwrites messages based on force flag.
	UpsertMessages(ctx context.Context, messages []common.MessageWithMetadata, force bool) error
	// GetCCVData retrieves existing CCV data for a message ID.
	GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]common.VerifierResultWithMetadata, error)
}

// AggregatorReaderFactory creates a new aggregator reader for replay.
// The caller is responsible for closing the returned reader.
type AggregatorReaderFactory func(since int64) (*readers.ResilientReader, error)

// Engine orchestrates replay jobs with crash-recovery support.
type Engine struct {
	store                   *Store
	storage                 Storage
	registry                *registry.VerifierRegistry
	aggregatorReaderFactory AggregatorReaderFactory
	lggr                    logger.Logger
	batchThrottleDelay      time.Duration
}

type EngineOption func(*Engine)

func WithBatchThrottleDelay(d time.Duration) EngineOption {
	return func(e *Engine) { e.batchThrottleDelay = d }
}

func NewEngine(
	store *Store,
	storage Storage,
	reg *registry.VerifierRegistry,
	factory AggregatorReaderFactory,
	lggr logger.Logger,
	opts ...EngineOption,
) *Engine {
	e := &Engine{
		store:                   store,
		storage:                 storage,
		registry:                reg,
		aggregatorReaderFactory: factory,
		lggr:                    logger.Named(lggr, "ReplayEngine"),
		batchThrottleDelay:      500 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Start creates a new job or resumes a stale one, acquires the advisory lock,
// and runs the replay to completion.
func (e *Engine) Start(ctx context.Context, req Request) (string, error) {
	job, err := e.findOrCreateJob(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to prepare replay job: %w", err)
	}

	acquired, err := e.store.TryAdvisoryLock(ctx, job.ID)
	if err != nil {
		return job.ID, fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	if !acquired {
		return job.ID, ErrJobLocked
	}
	defer func() {
		_ = e.store.ReleaseAdvisoryLock(ctx, job.ID)
	}()

	e.lggr.Infow("Starting replay", "jobID", job.ID, "type", job.Type, "force", job.ForceOverwrite, "cursor", job.ProgressCursor)

	err = e.runJob(ctx, job)
	if err != nil {
		errMsg := err.Error()
		if markErr := e.store.MarkFailed(ctx, job.ID, errMsg); markErr != nil {
			e.lggr.Errorw("Failed to mark job as failed", "jobID", job.ID, "error", markErr)
		}
		return job.ID, fmt.Errorf("replay job %s failed: %w", job.ID, err)
	}

	if markErr := e.store.MarkCompleted(ctx, job.ID); markErr != nil {
		e.lggr.Errorw("Failed to mark job as completed", "jobID", job.ID, "error", markErr)
		return job.ID, markErr
	}

	e.lggr.Infow("Replay completed", "jobID", job.ID)
	return job.ID, nil
}

// Resume resumes a specific job by ID.
func (e *Engine) Resume(ctx context.Context, jobID string) error {
	job, err := e.store.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to load job %s: %w", jobID, err)
	}

	if job.Status != StatusRunning && job.Status != StatusFailed {
		return fmt.Errorf("job %s is in status %s, only running or failed jobs can be resumed", jobID, job.Status)
	}

	acquired, err := e.store.TryAdvisoryLock(ctx, job.ID)
	if err != nil {
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	if !acquired {
		return ErrJobLocked
	}
	defer func() {
		_ = e.store.ReleaseAdvisoryLock(ctx, job.ID)
	}()

	e.lggr.Infow("Resuming replay", "jobID", job.ID, "type", job.Type, "cursor", job.ProgressCursor)

	err = e.runJob(ctx, job)
	if err != nil {
		errMsg := err.Error()
		if markErr := e.store.MarkFailed(ctx, job.ID, errMsg); markErr != nil {
			e.lggr.Errorw("Failed to mark job as failed", "jobID", job.ID, "error", markErr)
		}
		return fmt.Errorf("replay job %s failed: %w", job.ID, err)
	}

	if markErr := e.store.MarkCompleted(ctx, job.ID); markErr != nil {
		return markErr
	}

	e.lggr.Infow("Replay completed", "jobID", job.ID)
	return nil
}

func (e *Engine) Status(ctx context.Context, jobID string) (*Job, error) {
	return e.store.GetJob(ctx, jobID)
}

func (e *Engine) List(ctx context.Context) ([]Job, error) {
	return e.store.ListJobs(ctx)
}

func (e *Engine) findOrCreateJob(ctx context.Context, req Request) (*Job, error) {
	existing, err := e.store.FindResumable(ctx, req)
	if err == nil {
		e.lggr.Infow("Found resumable job", "jobID", existing.ID, "cursor", existing.ProgressCursor)
		return existing, nil
	}
	if !errors.Is(err, ErrNoResumable) {
		return nil, err
	}

	job, err := e.store.CreateJob(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create replay job: %w", err)
	}
	e.lggr.Infow("Created new replay job", "jobID", job.ID)
	return job, nil
}

func (e *Engine) runJob(ctx context.Context, job *Job) error {
	switch job.Type {
	case TypeDiscovery:
		return e.runDiscoveryReplay(ctx, job)
	case TypeMessages:
		return e.runMessageReplay(ctx, job)
	default:
		return fmt.Errorf("unknown replay type: %s", job.Type)
	}
}
