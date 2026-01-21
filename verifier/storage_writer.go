package verifier

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// StorageWriterProcessor handles batching and writing CCVNodeData to the offchain storage.
// It represents the final stage (3rd step) in the verifier processing pipeline.
//
// We assume here that all failures are transient and can be retried. (e.g. network issues).
// Therefore, on failure to write a batch, we schedule a retry after a configured retryDelay.
// Retry logic is handled by the batcher component and for now we follow linear backoff.
type StorageWriterProcessor struct {
	services.StateMachine
	wg sync.WaitGroup

	lggr           logger.Logger
	verifierID     string
	messageTracker MessageLatencyTracker

	retryDelay time.Duration
	storage    protocol.CCVNodeDataWriter
	batcher    *batcher.Batcher[protocol.VerifierNodeResult]

	// Pending writing tracker (shared with SRS and TVP)
	writingTracker *PendingWritingTracker

	// ChainStatus management for checkpoint writing
	chainStatusManager protocol.ChainStatusManager
}

func NewStorageBatcherProcessor(
	ctx context.Context,
	lggr logger.Logger,
	verifierID string,
	messageTracker MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	config CoordinatorConfig,
	writingTracker *PendingWritingTracker,
	chainStatusManager protocol.ChainStatusManager,
) (*StorageWriterProcessor, *batcher.Batcher[protocol.VerifierNodeResult], error) {
	storageBatchSize, storageBatchTimeout, retryDelay := configWithDefaults(lggr, config)
	storageBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](
		ctx,
		storageBatchSize,
		storageBatchTimeout,
		1,
	)

	processor := &StorageWriterProcessor{
		lggr:               lggr,
		verifierID:         verifierID,
		messageTracker:     messageTracker,
		storage:            storage,
		batcher:            storageBatcher,
		retryDelay:         retryDelay,
		writingTracker:     writingTracker,
		chainStatusManager: chainStatusManager,
	}
	return processor, storageBatcher, nil
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

func (s *StorageWriterProcessor) Start(ctx context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.run(ctx)
		})
		return nil
	})
}

func (s *StorageWriterProcessor) Close() error {
	return s.StopOnce(s.Name(), func() error {
		s.wg.Wait()
		return nil
	})
}

func (s *StorageWriterProcessor) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-s.batcher.OutChannel():
			if !ok {
				s.lggr.Infow("Storage batcher channel closed")
				return
			}

			// Handle batch-level errors from batcher (should be rare)
			// TODO In this case we don't retry the batch, should we?
			if batch.Error != nil {
				s.lggr.Errorw("Batch-level error from CCVData batcher",
					"error", batch.Error,
					"errorType", "batcher_failure")
				continue
			}

			if len(batch.Items) == 0 {
				s.lggr.Debugw("Received empty CCVData batch")
				continue
			}

			// Write batch of CCVData to offchain storage
			if err := s.storage.WriteCCVNodeData(ctx, batch.Items); err != nil {
				s.lggr.Errorw("Failed to write CCV data batch to storage, scheduling retry",
					"error", err,
					"batchSize", len(batch.Items),
					"retryDelay", s.retryDelay,
				)

				// Retry the failed batch after configured delay
				if retryErr := s.batcher.Retry(s.retryDelay, batch.Items...); retryErr != nil {
					s.lggr.Errorw("Failed to schedule retry for CCV data batch",
						"error", retryErr,
						"batchSize", len(batch.Items),
					)
				}
				continue
			}

			s.lggr.Infow("CCV data batch stored successfully",
				"batchSize", len(batch.Items),
			)

			// Success: remove from tracker and update checkpoints
			affectedChains := make(map[protocol.ChainSelector]struct{})
			for _, item := range batch.Items {
				chain := item.Message.SourceChainSelector
				s.writingTracker.Remove(chain, item.MessageID.String())
				affectedChains[chain] = struct{}{}
			}

			s.updateCheckpoints(ctx, affectedChains)
			s.messageTracker.TrackMessageLatencies(ctx, batch.Items)
		}
	}
}

func (s *StorageWriterProcessor) updateCheckpoints(ctx context.Context, chains map[protocol.ChainSelector]struct{}) {
	var statuses []protocol.ChainStatusInfo

	for chain := range chains {
		checkpoint, shouldWrite := s.writingTracker.CheckpointIfAdvanced(chain)
		if !shouldWrite {
			continue
		}

		statuses = append(statuses, protocol.ChainStatusInfo{
			ChainSelector:        chain,
			FinalizedBlockHeight: big.NewInt(int64(checkpoint)),
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

func (s *StorageWriterProcessor) Name() string {
	return fmt.Sprintf("verifier.StorageWriterProcessor[%s]", s.verifierID)
}

func (s *StorageWriterProcessor) HealthReport() map[string]error {
	report := make(map[string]error)
	report[s.Name()] = s.Ready()
	return report
}

var (
	_ services.Service        = (*StorageWriterProcessor)(nil)
	_ protocol.HealthReporter = (*StorageWriterProcessor)(nil)
)
