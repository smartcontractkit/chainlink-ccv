package verifier

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// NewQueueBatcherAdapter creates a batcher that forwards results to a durable queue.
// It creates a real Batcher instance and spawns a goroutine to consume from it and publish to the queue.
func NewQueueBatcherAdapter(
	ctx context.Context,
	queue jobqueue.JobQueue[protocol.VerifierNodeResult],
	lggr logger.Logger,
	maxSize int,
	maxWait time.Duration,
) *batcher.Batcher[protocol.VerifierNodeResult] {
	// Create a real batcher
	b := batcher.NewBatcher[protocol.VerifierNodeResult](ctx, maxSize, maxWait, 10)

	// Start a goroutine to forward batches from the batcher to the queue
	var wg sync.WaitGroup
	wg.Go(func() {
		forwardToQueue(ctx, b.OutChannel(), queue, lggr)
	})

	// Ensure cleanup
	go func() {
		<-ctx.Done()
		wg.Wait()
	}()

	return b
}

// forwardToQueue consumes from the batcher's output channel and publishes to the queue.
func forwardToQueue(
	ctx context.Context,
	batchChan <-chan batcher.BatchResult[protocol.VerifierNodeResult],
	queue jobqueue.JobQueue[protocol.VerifierNodeResult],
	lggr logger.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-batchChan:
			if !ok {
				return
			}

			// Handle batch errors
			if batch.Error != nil {
				lggr.Errorw("Received error batch, skipping", "error", batch.Error)
				continue
			}

			// Publish items to queue
			if len(batch.Items) > 0 {
				publishCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if err := queue.Publish(publishCtx, batch.Items...); err != nil {
					lggr.Errorw("Failed to publish to queue", "error", err, "count", len(batch.Items))
				} else {
					lggr.Debugw("Published results to queue", "count", len(batch.Items))
				}
				cancel()
			}
		}
	}
}
