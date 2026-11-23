package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc/pool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	defaultPollInterval = 1 * time.Second
	// leaseMargin is added to the worker timeout, so a slow but live attempt keeps its lease.
	leaseMargin = 30 * time.Second
	// expireInterval is how often PROCESSING messages past their deadline are timed out.
	expireInterval  = 1 * time.Minute
	expireBatchSize = 1000
	// expireMaxBatches bounds one expire tick; expiry has its own loop, so it never delays claims.
	expireMaxBatches        = 50
	storageOperationTimeout = 10 * time.Second
	// maxConsecutiveClaimErrors makes the pool not ready when the database cannot be read.
	maxConsecutiveClaimErrors = 10
)

// errUnrecoverable marks an attempt that no retry can complete.
var errUnrecoverable = errors.New("unrecoverable")

// LeaderChecker tells if this replica is the discovery leader.
type LeaderChecker interface {
	// IsLeader returns true while this replica holds the discovery lock.
	IsLeader() bool
}

// Pool claims due PROCESSING messages from the database and fetches their verifications. Every replica runs one.
type Pool struct {
	config       config.PoolConfig
	baseDelay    time.Duration
	maxDelay     time.Duration
	lease        time.Duration
	pollInterval time.Duration
	// expireInterval is a field so tests can shorten it.
	expireInterval time.Duration
	logger         logger.Logger
	registry       *registry.VerifierRegistry
	storage        common.IndexerStorage
	leader         LeaderChecker
	recordSize     func(ctx context.Context, size int64)
	metrics        common.IndexerMetricLabeler

	inFlight               atomic.Int64
	consecutiveClaimErrors atomic.Uint32
	wake                   chan struct{}
	// starved records that due work may wait for a free worker slot.
	starved    atomic.Bool
	pool       *pool.Pool
	wg         sync.WaitGroup
	cancelFunc context.CancelFunc
	running    atomic.Bool
}

// NewWorkerPool creates a Pool.
func NewWorkerPool(lggr logger.Logger, poolCfg config.PoolConfig, schedulerCfg config.SchedulerConfig, registry *registry.VerifierRegistry, storage common.IndexerStorage) (*Pool, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry must be specified")
	}
	if storage == nil {
		return nil, fmt.Errorf("storage must be specified")
	}
	if poolCfg.ConcurrentWorkers <= 0 {
		return nil, fmt.Errorf("concurrent workers must be positive")
	}
	pollInterval := time.Duration(poolCfg.PollInterval) * time.Millisecond
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}

	p := &Pool{
		config:         poolCfg,
		baseDelay:      time.Duration(schedulerCfg.BaseDelay) * time.Millisecond,
		maxDelay:       time.Duration(schedulerCfg.MaxDelay) * time.Millisecond,
		lease:          time.Duration(poolCfg.WorkerTimeout)*time.Second + leaseMargin,
		pollInterval:   pollInterval,
		expireInterval: expireInterval,
		logger:         lggr,
		registry:       registry,
		storage:        storage,
		pool:           pool.New().WithMaxGoroutines(poolCfg.ConcurrentWorkers),
		wake:           make(chan struct{}, 1),
	}
	// Primed: work that exists before this process started has no local wakeup.
	p.Wake()
	return p, nil
}

// SetLeadership limits the expire sweep and the size metric to the leader. Without it, every replica runs them.
func (p *Pool) SetLeadership(l LeaderChecker) {
	p.leader = l
}

// SetSizeRecorder sets the metric callback for the number of PROCESSING messages.
func (p *Pool) SetSizeRecorder(fn func(ctx context.Context, size int64)) {
	p.recordSize = fn
}

// SetMetrics sets the labeler that tasks use to record metrics. Call it before Start.
func (p *Pool) SetMetrics(m common.IndexerMetricLabeler) {
	p.metrics = m
}

// Wake makes the pool claim at once, for example after a discovery commit.
func (p *Pool) Wake() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Start begins claiming work.
func (p *Pool) Start(ctx context.Context) {
	childCtx, cancelFunc := context.WithCancel(ctx)
	p.cancelFunc = cancelFunc
	p.running.Store(true)
	p.wg.Go(func() { p.run(childCtx) })
	p.wg.Go(func() { p.runExpire(childCtx) })
}

// Stop stops claiming and waits for in-flight attempts; each is bounded by WorkerTimeout.
func (p *Pool) Stop() {
	p.logger.Info("Stopping WorkerPool")
	if p.cancelFunc != nil {
		p.cancelFunc()
	}
	p.wg.Wait()
	p.pool.Wait()
	p.running.Store(false)
	p.logger.Info("Stopped WorkerPool")
}

// Ready reports an error when the pool is not running or cannot claim work.
func (p *Pool) Ready() error {
	if !p.running.Load() {
		return errors.New("worker pool not running")
	}
	if n := p.consecutiveClaimErrors.Load(); n >= maxConsecutiveClaimErrors {
		return fmt.Errorf("worker claim failed %d times in a row", n)
	}
	return nil
}

func (p *Pool) HealthReport() map[string]error {
	return map[string]error{p.Name(): p.Ready()}
}

func (p *Pool) Name() string {
	return "indexer_worker_pool"
}

func (p *Pool) run(ctx context.Context) {
	pollTicker := time.NewTicker(p.pollInterval)
	defer pollTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Exiting WorkerPool, due to context cancellation")
			return
		case <-p.wake:
			p.claim(ctx)
		case <-pollTicker.C:
			p.claim(ctx)
		}
	}
}

// runExpire runs expiry in its own goroutine, so a backlog or a slow database does not stop claims.
func (p *Pool) runExpire(ctx context.Context) {
	ticker := time.NewTicker(p.expireInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.expire(ctx)
		}
	}
}

// claim leases at most one message per free worker slot, so a claimed message starts at once.
func (p *Pool) claim(ctx context.Context) {
	// Set before reading inFlight, so a worker that finishes in between still wakes the pool.
	p.starved.Store(true)
	free := p.config.ConcurrentWorkers - int(p.inFlight.Load())
	if free <= 0 || ctx.Err() != nil {
		return
	}
	// A claim canceled after commit leaves messages leased with no worker until the lease ends, so finish it.
	claimCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storageOperationTimeout)
	claims, err := p.storage.ClaimWork(claimCtx, free, p.lease)
	cancel()
	if err != nil {
		p.consecutiveClaimErrors.Add(1)
		p.logger.Errorw("Failed to claim messages", "error", err)
		return
	}
	p.consecutiveClaimErrors.Store(0)
	if len(claims) < free {
		p.starved.Store(false)
	}
	for _, c := range claims {
		p.inFlight.Add(1)
		p.pool.Go(func() {
			defer p.releaseSlot()
			p.process(context.WithoutCancel(ctx), c)
		})
	}
}

// releaseSlot frees a worker slot and wakes the pool if due work waited for one.
func (p *Pool) releaseSlot() {
	p.inFlight.Add(-1)
	if p.starved.Swap(false) {
		p.Wake()
	}
}

func (p *Pool) process(ctx context.Context, c common.WorkClaim) {
	workerCtx, cancel := context.WithTimeout(ctx, time.Duration(p.config.WorkerTimeout)*time.Second)
	defer cancel()
	if c.TraceParent != "" {
		carrier := propagation.MapCarrier{"traceparent": c.TraceParent}
		workerCtx = otel.GetTextMapPropagator().Extract(workerCtx, carrier)
	}
	result, err := p.execute(workerCtx, c)

	s := common.WorkSettlement{MessageID: c.MessageID, Attempt: c.Attempt}
	switch {
	case err == nil && result.UnavailableCCVs == 0:
		s.Status = common.MessageSuccessful
	case errors.Is(err, errUnrecoverable):
		s.Status, s.LastErr = common.MessageTimeout, err.Error()
	default:
		s.Status = common.MessageProcessing
		if err != nil {
			s.LastErr = err.Error()
		}
		s.RetryDelay = ccvcommon.BackoffDelay(c.Attempt+1, p.baseDelay, 2, p.maxDelay)
	}

	opCtx, opCancel := context.WithTimeout(ctx, storageOperationTimeout)
	defer opCancel()
	status, settleErr := p.storage.SettleWork(opCtx, s)
	switch {
	case errors.Is(settleErr, common.ErrClaimLost):
		p.logger.Debugw("Claim lost before settle, a different worker owns the message", "messageID", c.MessageID.String())
	case settleErr != nil:
		p.logger.Errorw("Failed to settle message, it is claimed again when the lease ends", "messageID", c.MessageID.String(), "error", settleErr)
	case status == common.MessageSuccessful && result != nil && result.SuccessfulVerifications > 0:
		// PER-MESSAGE LOG (success): gated on SuccessfulVerifications so it fires once per message.
		p.logger.Infow("Message processing finished",
			protocol.LogTypeKey, protocol.LogTypeMessageSuccess,
			"messageID", c.MessageID.String(),
			"status", "verified",
		)
	case status == common.MessageTimeout:
		// PER-MESSAGE LOG (failure): shares its message string with the success path.
		p.logger.Warnw("Message processing finished",
			protocol.LogTypeKey, protocol.LogTypeMessageFailure,
			"messageID", c.MessageID.String(),
			"status", "timeout",
			"error", s.LastErr,
		)
	}
}

// execute loads the message and runs the task, and recovers a panic as an error.
func (p *Pool) execute(ctx context.Context, c common.WorkClaim) (result *TaskResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Errorw("Panic during worker attempt", "messageID", c.MessageID.String(), "panic", r)
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	msg, err := p.storage.GetMessage(ctx, c.MessageID)
	if errors.Is(err, storage.ErrMessageNotFound) {
		return nil, fmt.Errorf("%w: %w", errUnrecoverable, err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load message: %w", err)
	}

	task, err := NewTask(p.logger, protocol.VerifierResult{
		MessageID:           c.MessageID,
		Message:             msg.Message,
		MessageCCVAddresses: msg.MessageCCVAddresses,
	}, p.registry, p.storage)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnrecoverable, err)
	}
	task.attempt = c.Attempt
	task.metrics = p.metrics
	return Execute(ctx, task)
}

// expire times out messages past their deadline and records the backlog size, on the leader only.
func (p *Pool) expire(ctx context.Context) {
	if p.leader != nil && !p.leader.IsLeader() {
		return
	}
	var total int64
	for range expireMaxBatches {
		if ctx.Err() != nil {
			return
		}
		eCtx, cancel := context.WithTimeout(ctx, storageOperationTimeout)
		n, err := p.storage.ExpireWork(eCtx, expireBatchSize)
		cancel()
		total += n
		if err != nil {
			p.logger.Errorw("Failed to expire messages", "error", err)
			break
		}
		if n < expireBatchSize {
			break
		}
	}
	if total > 0 {
		p.logger.Infow("Timed out messages past their retry deadline", "count", total)
	}
	if p.recordSize == nil {
		return
	}
	cCtx, cancel := context.WithTimeout(ctx, storageOperationTimeout)
	defer cancel()
	if n, err := p.storage.CountProcessingMessages(cCtx); err != nil {
		p.logger.Warnw("Failed to count processing messages", "error", err)
	} else {
		p.recordSize(ctx, n)
	}
}
