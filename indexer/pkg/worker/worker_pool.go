package worker

import (
	"context"
	"time"

	"github.com/panjf2000/ants/v2"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Pool struct {
	config           Config
	logger           logger.Logger
	pool             *ants.Pool
	discoveryChannel <-chan protocol.CCVData
	registry         *registry.VerifierRegistry
	storage          common.IndexerStorage
}

type Config struct {
	WorkerTimeout time.Duration
}

// NewWorkerPool creates a new WorkerPool with the given configuration.
func NewWorkerPool(logger logger.Logger, config Config, discoveryChannel <-chan protocol.CCVData, registry *registry.VerifierRegistry, storage common.IndexerStorage) *Pool {
	pool, err := ants.NewPool(1000, ants.WithMaxBlockingTasks(1024), ants.WithNonblocking(false))
	if err != nil {
		logger.Fatalf("Unable to start worker pool: %v", err)
	}

	return &Pool{
		config:           config,
		logger:           logger,
		pool:             pool,
		discoveryChannel: discoveryChannel,
		registry:         registry,
		storage:          storage,
	}
}

// Start begins processing messages from the discovery channel.
func (p *Pool) Start(ctx context.Context) {
	go p.run(ctx)
}

func (p *Pool) run(ctx context.Context) {
	defer p.pool.Release()

	for {
		select {
		case <-ctx.Done():
			return
		case message, ok := <-p.discoveryChannel:
			p.logger.Info("Starting Worker!")
			if !ok {
				return
			}
			taskCtx, cancel := context.WithTimeout(ctx, p.config.WorkerTimeout)
			p.logger.Infof("Starting Worker for %s", message.MessageID.String())

			if err := p.pool.Submit(func() {
				defer cancel()
				task, err := NewTask(taskCtx, p.logger, message, p.registry, p.storage)
				if err != nil {
					// TODO: Handle error here into a DLQ
					return
				}

				if _, err := Execute(task); err != nil {
					// TODO: Handle error here into a DLQ
					return
				}
			}); err != nil {
				cancel()
				// TODO: Handle pool submission error here into a DLQ
			}
		}
	}
}
