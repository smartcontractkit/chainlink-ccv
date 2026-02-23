package verifier

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// forwardTasksToQueue reads ready VerificationTasks from a SourceReaderService batcher
// channel and publishes them to the durable task queue.
// It exits when ctx is canceled or the channel is closed.
func forwardTasksToQueue(
	ctx context.Context,
	ch <-chan batcher.BatchResult[VerificationTask],
	queue jobqueue.JobQueue[VerificationTask],
	lggr logger.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-ch:
			if !ok {
				return
			}
			if batch.Error != nil {
				lggr.Errorw("Error batch received from SourceReaderService, skipping", "error", batch.Error)
				continue
			}
			if len(batch.Items) == 0 {
				continue
			}
			if err := queue.Publish(ctx, batch.Items...); err != nil {
				lggr.Errorw("Failed to publish tasks to queue", "error", err, "count", len(batch.Items))
			}
		}
	}
}
