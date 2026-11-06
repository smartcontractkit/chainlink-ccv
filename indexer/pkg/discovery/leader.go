package discovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// maxConsecutiveElectionErrors is the number of failed lock operations in a row that makes the elector unhealthy.
const maxConsecutiveElectionErrors = 3

// LeadershipGate tells a discovery source if this replica is the discovery leader.
type LeadershipGate interface {
	// LeaderContext returns a context that is canceled when leadership is lost, and false for a follower.
	// electionCount increases each time this replica becomes leader, so a caller can see a new leadership.
	LeaderContext() (ctx context.Context, electionCount uint64, isLeader bool)
}

var (
	_ LeadershipGate          = (*LeaderElector)(nil)
	_ protocol.HealthReporter = (*LeaderElector)(nil)
)

// LeaderElectorConfig holds the timings of the discovery leader election.
type LeaderElectorConfig struct {
	// LeaseTimeout is the time after which the database frees the lock of a leader that sends no heartbeat.
	LeaseTimeout time.Duration
	// HeartbeatInterval is the time between two heartbeats of the leader. It must be less than LeaseTimeout.
	HeartbeatInterval time.Duration
	// AcquireInterval is the time between two attempts of a follower to get the lock.
	AcquireInterval time.Duration
}

// LeaderElectorOption changes an optional setting of a LeaderElector.
type LeaderElectorOption func(*LeaderElector)

// WithOnElected adds a callback that runs in its own goroutine each time this replica becomes leader.
// The callback context is canceled when leadership is lost.
func WithOnElected(fn func(ctx context.Context)) LeaderElectorOption {
	return func(e *LeaderElector) { e.onElected = append(e.onElected, fn) }
}

// LeaderElector holds the discovery lock so that one indexer replica at a time runs discovery.
type LeaderElector struct {
	locker    common.DiscoveryLocker
	cfg       LeaderElectorConfig
	lggr      logger.Logger
	metrics   common.IndexerMetricLabeler
	onElected []func(ctx context.Context)

	mu                sync.RWMutex
	leaderCtx         context.Context
	electionCount     uint64
	started           bool
	consecutiveErrors uint
	lastError         error

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewLeaderElector(
	locker common.DiscoveryLocker,
	cfg LeaderElectorConfig,
	lggr logger.Logger,
	metrics common.IndexerMetricLabeler,
	opts ...LeaderElectorOption,
) (*LeaderElector, error) {
	if locker == nil || lggr == nil || metrics == nil {
		return nil, errors.New("locker, logger and metrics must be specified")
	}
	if cfg.HeartbeatInterval <= 0 || cfg.AcquireInterval <= 0 || cfg.HeartbeatInterval >= cfg.LeaseTimeout {
		return nil, errors.New("heartbeat and acquire intervals must be positive, and heartbeat interval less than lease timeout")
	}
	e := &LeaderElector{
		locker:  locker,
		cfg:     cfg,
		lggr:    logger.Named(lggr, "LeaderElector"),
		metrics: metrics,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// Start begins the election loop in a goroutine.
func (e *LeaderElector) Start(ctx context.Context) {
	ctx, e.cancel = context.WithCancel(ctx)
	e.mu.Lock()
	e.started = true
	e.mu.Unlock()
	e.wg.Add(1)
	go e.run(ctx)
}

// Close stops the election loop and releases the lock if this replica holds it.
func (e *LeaderElector) Close() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
}

func (e *LeaderElector) LeaderContext() (context.Context, uint64, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leaderCtx, e.electionCount, e.leaderCtx != nil
}

// IsLeader reports if this replica is the discovery leader.
func (e *LeaderElector) IsLeader() bool {
	_, _, ok := e.LeaderContext()
	return ok
}

// Ready returns an error when the lock operations failed too many times in a row. A follower is ready.
func (e *LeaderElector) Ready() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.started {
		return errors.New("leader elector not started")
	}
	if e.consecutiveErrors >= maxConsecutiveElectionErrors {
		return fmt.Errorf("discovery lock failed %d times in a row. Last error: %w", e.consecutiveErrors, e.lastError)
	}
	return nil
}

func (e *LeaderElector) HealthReport() map[string]error {
	return map[string]error{e.Name(): e.Ready()}
}

func (e *LeaderElector) Name() string {
	return "indexer.LeaderElector"
}

func (e *LeaderElector) run(ctx context.Context) {
	defer e.wg.Done()
	e.metrics.RecordDiscoveryLeaderGauge(ctx, false)
	for {
		if lock := e.tryAcquire(ctx); lock != nil {
			e.lead(ctx, lock)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.cfg.AcquireInterval):
		}
	}
}

// recordResult tracks consecutive lock errors for the health report. A nil err resets the count.
func (e *LeaderElector) recordResult(ctx context.Context, op string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.consecutiveErrors = 0
		e.lastError = nil
		return
	}
	e.consecutiveErrors++
	e.lastError = err
	e.metrics.IncrementDiscoveryLeaderErrors(ctx, op)
}

func (e *LeaderElector) tryAcquire(ctx context.Context) common.DiscoveryLock {
	acquireCtx, cancel := context.WithTimeout(ctx, e.cfg.AcquireInterval)
	defer cancel()
	lock, acquired, err := e.locker.TryAcquireDiscoveryLock(acquireCtx, e.cfg.LeaseTimeout)
	if err != nil && ctx.Err() != nil {
		return nil
	}
	e.recordResult(ctx, "acquire", err)
	if err != nil {
		e.lggr.Warnw("Failed to try the discovery lock", "error", err)
		return nil
	}
	if !acquired {
		return nil
	}
	return lock
}

// lead runs while this replica holds the lock, and returns when a heartbeat fails or ctx is done.
func (e *LeaderElector) lead(ctx context.Context, lock common.DiscoveryLock) {
	leaderCtx, cancelLeader := context.WithCancel(ctx)
	e.mu.Lock()
	e.leaderCtx = leaderCtx //nolint:fatcontext // the elector gives the current leadership context to callers
	e.electionCount++
	e.mu.Unlock()
	e.lggr.Infow("Elected discovery leader")
	e.metrics.RecordDiscoveryLeaderGauge(ctx, true)
	e.metrics.IncrementDiscoveryLeaderChanges(ctx)

	var callbacksWG sync.WaitGroup
	for _, fn := range e.onElected {
		callbacksWG.Go(func() { fn(leaderCtx) })
	}

	e.heartbeat(leaderCtx, lock)

	e.mu.Lock()
	e.leaderCtx = nil
	e.mu.Unlock()
	cancelLeader()
	callbacksWG.Wait()
	lock.Release()
	e.lggr.Infow("Stopped being discovery leader")
	e.metrics.RecordDiscoveryLeaderGauge(context.WithoutCancel(ctx), false)
}

func (e *LeaderElector) heartbeat(leaderCtx context.Context, lock common.DiscoveryLock) {
	ticker := time.NewTicker(e.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-leaderCtx.Done():
			return
		case <-ticker.C:
			hbCtx, cancel := context.WithTimeout(leaderCtx, e.cfg.HeartbeatInterval)
			err := lock.Heartbeat(hbCtx)
			cancel()
			if err != nil && leaderCtx.Err() != nil {
				return
			}
			e.recordResult(leaderCtx, "heartbeat", err)
			if err != nil {
				e.lggr.Warnw("Discovery lock heartbeat failed, stopping leadership", "error", err)
				return
			}
		}
	}
}
