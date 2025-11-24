package worker

import (
	"context"
	"time"

	"github.com/panjf2000/ants/v2"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Pool struct {
	config           config.PoolConfig
	logger           logger.Logger
	pool             *ants.Pool
	discoveryChannel <-chan protocol.VerifierResult
	scheduler        *Scheduler
	registry         *registry.VerifierRegistry
	storage          common.IndexerStorage
}

// NewWorkerPool creates a new WorkerPool with the given configuration.
func NewWorkerPool(logger logger.Logger, config config.PoolConfig, discoveryChannel <-chan protocol.VerifierResult, scheduler *Scheduler, registry *registry.VerifierRegistry, storage common.IndexerStorage) *Pool {
	pool, err := ants.NewPool(config.ConcurrentWorkers, ants.WithMaxBlockingTasks(1024), ants.WithNonblocking(false))
	if err != nil {
		logger.Fatalf("Unable to start worker pool: %v", err)
	}

	return &Pool{
		config:           config,
		logger:           logger,
		pool:             pool,
		discoveryChannel: discoveryChannel,
		scheduler:        scheduler,
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
			if !ok {
				continue
			}
			p.logger.Infow("Enqueueing new Message", "messageID", message.MessageID.String())
			task, err := NewTask(p.logger, message, p.registry, p.storage, p.scheduler.VerificationVisibilityWindow())
			// This shouldn't happen, it can only be caused by an invalid hex conversion.
			// We're unable to retry the message or send it to the DLQ.
			if err != nil {
				p.logger.Error("Unable to create Task. this shouldn't happen.", err)
				continue
			}

			if err = p.scheduler.Enqueue(ctx, task); err != nil {
				p.logger.Errorf("Unable to enqueue: %v", err)
				continue
			}
		case task, ok := <-p.scheduler.Ready():
			if !ok {
				continue
			}

			workerCtx, cancel := context.WithTimeout(ctx, time.Duration(p.config.WorkerTimeout)*time.Second)
			p.logger.Infof("Starting Worker for %s", task.messageID.String())

			if err := p.pool.Submit(func() {
				defer cancel()
				result, err := Execute(workerCtx, task)
				if p.shouldRetry(result, err) {
					if err != nil {
						task.lastErr = err
					}

					// Enqueue the Task
					if err = p.scheduler.Enqueue(ctx, task); err != nil {
						p.logger.Error(err)
					}
				}
			}); err != nil {
				cancel()
				p.logger.Errorf("Pool full! Unable to execute message %s retrying", task.messageID.String())
				if err := p.scheduler.Enqueue(ctx, task); err != nil {
					p.logger.Errorf("Unable to enqueue: %v", err)
				}
			}
		case task, ok := <-p.scheduler.DLQ():
			if !ok {
				continue
			}
			p.logger.Warnf("Message %s entered DLQ. Partial verifications may have been recieved", task.messageID.String())
			// TODO: DLQ Logic here...
		}
	}
}

func (p *Pool) shouldRetry(result *TaskResult, err error) bool {
	return err != nil || result.UnavailableCCVs > 0
}
