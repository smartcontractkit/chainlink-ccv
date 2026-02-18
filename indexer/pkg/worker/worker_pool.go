package worker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sourcegraph/conc/pool"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Pool struct {
	config           config.PoolConfig
	logger           logger.Logger
	pool             *pool.Pool
	discoveryChannel <-chan common.VerifierResultWithMetadata
	scheduler        *Scheduler
	registry         *registry.VerifierRegistry
	storage          common.IndexerStorage
	wg               sync.WaitGroup
	cancelFunc       context.CancelFunc
}

// NewWorkerPool creates a new WorkerPool with the given configuration.
func NewWorkerPool(logger logger.Logger, config config.PoolConfig, discoveryChannel <-chan common.VerifierResultWithMetadata, scheduler *Scheduler, registry *registry.VerifierRegistry, storage common.IndexerStorage) (*Pool, error) {
	// create a conc pool with the requested max goroutines
	concPool := pool.New().WithMaxGoroutines(config.ConcurrentWorkers)

	if discoveryChannel == nil {
		return nil, fmt.Errorf("discovery channel must be specified")
	}

	if scheduler == nil {
		return nil, fmt.Errorf("scheduler must be specified")
	}

	if registry == nil {
		return nil, fmt.Errorf("registry must be specified")
	}

	if storage == nil {
		return nil, fmt.Errorf("storage must be specified")
	}

	return &Pool{
		config:           config,
		logger:           logger,
		pool:             concPool,
		discoveryChannel: discoveryChannel,
		scheduler:        scheduler,
		registry:         registry,
		storage:          storage,
	}, nil
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
	if p.cancelFunc != nil {
		p.cancelFunc()
	}
	p.wg.Wait()
	if p.pool != nil {
		p.pool.Wait()
	}
	p.logger.Info("Stopped WorkerPool")
}

func (p *Pool) run(ctx context.Context) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Exiting WorkerPool, due to context cancellation")
			return
		case task, ok := <-p.scheduler.Ready():
			if !ok {
				p.logger.Error("Scheduler ready channel closed; exiting worker pool run loop")
				return
			}

			workerCtx, cancel := context.WithTimeout(ctx, time.Duration(p.config.WorkerTimeout)*time.Second)
			p.logger.Infof("Starting Worker for %s", task.messageID.String())

			p.pool.Go(func() {
				defer cancel()
				result, err := Execute(workerCtx, task)

				// Mark success only if we have a result and no error
				if err == nil && result != nil && result.UnavailableCCVs == 0 {
					if err := task.SetMessageStatus(ctx, common.MessageSuccessful, ""); err != nil {
						p.logger.Errorf("Unable to update Message Status for MessageID %s", task.messageID.String())
					}
				}

				// Decide whether to retry
				if err != nil || (result != nil && result.UnavailableCCVs > 0) {
					if err != nil {
						task.lastErr = err
					}

					// Enqueue the Task
					if err = p.scheduler.Enqueue(ctx, task); err != nil {
						p.logger.Error(err)
					}
				}
			})
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
				p.logger.Error("Discovery channel closed; exiting enqueueMessages")
				return
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
				p.logger.Error("DLQ channel closed; exiting handleDLQ")
				return
			}
			p.logger.Warnf("Message %s entered DLQ. Partial verifications may have been recieved", task.messageID.String())
			// TODO: DLQ Logic here..
		}
	}
}
