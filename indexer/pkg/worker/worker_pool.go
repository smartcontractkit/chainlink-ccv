package worker

import (
	"context"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Pool struct {
	config           config.PoolConfig
	logger           logger.Logger
	pool             *ants.Pool
	discoveryChannel <-chan common.VerifierResultWithMetadata
	scheduler        *Scheduler
	registry         *registry.VerifierRegistry
	storage          common.IndexerStorage
	wg               sync.WaitGroup
	cancelFunc       context.CancelFunc
}

// NewWorkerPool creates a new WorkerPool with the given configuration.
func NewWorkerPool(logger logger.Logger, config config.PoolConfig, discoveryChannel <-chan common.VerifierResultWithMetadata, scheduler *Scheduler, registry *registry.VerifierRegistry, storage common.IndexerStorage) *Pool {
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
	p.wg.Add(3)
	childCtx, cancelFunc := context.WithCancel(ctx)
	p.cancelFunc = cancelFunc

	go p.run(childCtx)
	go p.enqueueMessages(childCtx)
	go p.handleDLQ(childCtx)
}

func (p *Pool) Stop() {
	p.logger.Info("Stopping WorkerPool")
	p.cancelFunc()
	p.wg.Wait()
	p.logger.Info("Stopepd WorkerPool")
}

func (p *Pool) run(ctx context.Context) {
	defer p.pool.Release()
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Exiting WorkerPool, due to context cancellation")
			return
		case task, ok := <-p.scheduler.Ready():
			if !ok {
				p.logger.Error("Scheduler ready channel closed! worker pool will no longer function")
				continue
			}

			workerCtx, cancel := context.WithTimeout(ctx, time.Duration(p.config.WorkerTimeout)*time.Second)
			p.logger.Infof("Starting Worker for %s", task.messageID.String())

			if err := p.pool.Submit(func() {
				defer cancel()
				result, err := Execute(workerCtx, task)

				if p.wasSuccessful(result) {
					if err := task.SetMessageStatus(ctx, common.MessageSuccessful, ""); err != nil {
						p.logger.Errorf("Unable to update Message Status for MessageID %s", task.messageID.String())
					}
				}

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
		}
	}
}

func (p *Pool) enqueueMessages(ctx context.Context) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Exiting EnqueueMessages")
			return
		case message, ok := <-p.discoveryChannel:
			if !ok {
				p.logger.Error("Discovery Channel closed, worker pool will no longer be able to enqueue messages correctly")
				continue
			}
			p.logger.Infow("Enqueueing new Message", "messageID", message.VerifierResult.MessageID.String())
			task, err := NewTask(p.logger, message.VerifierResult, p.registry, p.storage, p.scheduler.VerificationVisibilityWindow())
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
		}
	}
}

func (p *Pool) handleDLQ(ctx context.Context) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Exiting DLQ Queue")
			return
		case task, ok := <-p.scheduler.DLQ():
			if !ok {
				p.logger.Error("DLQ Queue closed, worker pool will be unable to continue processing")
				continue
			}
			p.logger.Warnf("Message %s entered DLQ. Partial verifications may have been recieved", task.messageID.String())
			// TODO: DLQ Logic here..
		}
	}
}

func (p *Pool) shouldRetry(result *TaskResult, err error) bool {
	return err != nil || result.UnavailableCCVs > 0
}

func (p *Pool) wasSuccessful(result *TaskResult) bool {
	return result.UnavailableCCVs == 0
}
