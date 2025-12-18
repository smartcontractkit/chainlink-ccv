package verifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

type StorageWriterProcessor struct {
	services.StateMachine
	wg sync.WaitGroup

	lggr           logger.Logger
	messageTracker MessageLatencyTracker

	storage          protocol.CCVNodeDataWriter
	batcher          *batcher.Batcher[protocol.VerifierNodeResult]
	batchedCCVDataCh chan batcher.BatchResult[protocol.VerifierNodeResult]
}

func NewStorageBatcherProcessor(
	ctx context.Context,
	lggr logger.Logger,
	messageTracker MessageLatencyTracker,
	storage protocol.CCVNodeDataWriter,
	config CoordinatorConfig,
) (*StorageWriterProcessor, *batcher.Batcher[protocol.VerifierNodeResult], error) {
	storageBatchSize, storageBatchTimeout := configWithDefaults(lggr, config)
	batchedCCVDataCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult])
	storageBatcher := batcher.NewBatcher(
		ctx,
		storageBatchSize,
		storageBatchTimeout,
		batchedCCVDataCh,
	)

	processor := &StorageWriterProcessor{
		lggr:             lggr,
		messageTracker:   messageTracker,
		storage:          storage,
		batcher:          storageBatcher,
		batchedCCVDataCh: batchedCCVDataCh,
	}
	err := processor.Start(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start storage batcher processor: %w", err)
	}

	return processor, storageBatcher, nil
}

func configWithDefaults(lggr logger.Logger, config CoordinatorConfig) (int, time.Duration) {
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

	return storageBatchSize, storageBatchTimeout
}

func (s *StorageWriterProcessor) Start(ctx context.Context) error {
	return s.StartOnce(s.Name(), func() error {
		s.wg.Go(func() {
			s.run(ctx)
		})
		return nil
	})
}

func (s *StorageWriterProcessor) Close(_ context.Context) error {
	return s.StopOnce(s.Name(), func() error {
		s.wg.Wait()
		return nil
	})
}

func (s *StorageWriterProcessor) Name() string {
	return "StorageWriterProcessor"
}

func (s *StorageWriterProcessor) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-s.batchedCCVDataCh:
			if !ok {
				s.lggr.Infow("Storage batcher channel closed")
				s.wg.Wait()
				return
			}

			// Handle batch-level errors from batcher (should be rare)
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

			// TODO: Run in Go Routine
			// Write batch of CCVData to offchain storage
			if err := s.storage.WriteCCVNodeData(ctx, batch.Items); err == nil {
				s.lggr.Infow("CCV data batch stored successfully",
					"batchSize", len(batch.Items),
				)
				s.messageTracker.TrackMessageLatencies(ctx, batch.Items)
			}
		}
	}
}
