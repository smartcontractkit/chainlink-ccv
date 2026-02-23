package verifier

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// TaskBatcherToQueueAdapter consumes VerificationTask batches from SourceReaderService batchers
// and publishes them to the verification_tasks job queue.
// This adapter bridges the gap between SourceReaderService (which pushes to batcher channels)
// and TaskVerifierProcessorDB (which reads from the job queue).
type TaskBatcherToQueueAdapter struct {
	services.StateMachine
	wg     sync.WaitGroup
	cancel context.CancelFunc

	lggr               logger.Logger
	verifierID         string
	taskQueue          jobqueue.JobQueue[VerificationTask]
	sourceReaderStates map[protocol.ChainSelector]*SourceReaderService
}

// NewTaskBatcherToQueueAdapter creates a new adapter that forwards verification tasks from
// SourceReaderService batchers to a job queue.
func NewTaskBatcherToQueueAdapter(
	lggr logger.Logger,
	verifierID string,
	taskQueue jobqueue.JobQueue[VerificationTask],
	sourceReaderStates map[protocol.ChainSelector]*SourceReaderService,
) (*TaskBatcherToQueueAdapter, error) {
	adapter := &TaskBatcherToQueueAdapter{
		lggr:               logger.With(lggr, "component", "TaskBatcherToQueueAdapter", "verifierID", verifierID),
		verifierID:         verifierID,
		taskQueue:          taskQueue,
		sourceReaderStates: sourceReaderStates,
	}
	return adapter, nil
}

func (a *TaskBatcherToQueueAdapter) Start(ctx context.Context) error {
	return a.StartOnce(a.Name(), func() error {
		cancelCtx, cancel := context.WithCancel(ctx)
		a.cancel = cancel

		// Start a goroutine for each source reader to consume from its ready tasks channel
		for chainSelector, srs := range a.sourceReaderStates {
			a.wg.Go(func() {
				a.runForChain(cancelCtx, chainSelector, srs)
			})
		}

		return nil
	})
}

func (a *TaskBatcherToQueueAdapter) Close() error {
	return a.StopOnce(a.Name(), func() error {
		a.cancel()
		a.wg.Wait()
		return nil
	})
}

func (a *TaskBatcherToQueueAdapter) runForChain(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	srs *SourceReaderService,
) {
	lggr := logger.With(a.lggr, "chainSelector", chainSelector)
	lggr.Infow("Started task batcher to queue adapter for chain")

	for {
		select {
		case <-ctx.Done():
			lggr.Infow("TaskBatcherToQueueAdapter shutting down for chain")
			return

		case batch, ok := <-srs.ReadyTasksChannel():
			if !ok {
				lggr.Infow("Ready tasks channel closed for chain")
				return
			}

			// Handle batch errors
			if batch.Error != nil {
				lggr.Errorw("Received error batch from SourceReaderService, skipping",
					"error", batch.Error)
				continue
			}

			// Publish tasks to queue
			if len(batch.Items) > 0 {
				publishCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if err := a.taskQueue.Publish(publishCtx, batch.Items...); err != nil {
					lggr.Errorw("Failed to publish tasks to queue",
						"error", err,
						"count", len(batch.Items))
					// Tasks are lost here - consider implementing retry logic
					// One option: retry the tasks back to the SRS batcher
					if retryErr := srs.RetryTasks(10*time.Second, batch.Items...); retryErr != nil {
						lggr.Errorw("Failed to retry tasks back to SRS batcher",
							"error", retryErr,
							"count", len(batch.Items))
					}
				} else {
					lggr.Debugw("Published tasks to queue",
						"count", len(batch.Items))
				}
				cancel()
			}
		}
	}
}

func (a *TaskBatcherToQueueAdapter) Name() string {
	return "verifier.TaskBatcherToQueueAdapter[" + a.verifierID + "]"
}

func (a *TaskBatcherToQueueAdapter) HealthReport() map[string]error {
	report := make(map[string]error)
	report[a.Name()] = a.Ready()
	return report
}

var (
	_ services.Service        = (*TaskBatcherToQueueAdapter)(nil)
	_ protocol.HealthReporter = (*TaskBatcherToQueueAdapter)(nil)
)
