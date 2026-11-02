package discovery

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// LeadershipGate tells a discovery source if this replica is the discovery leader.
type LeadershipGate interface {
	// LeaderContext returns a context that is canceled when leadership is lost, and false for a follower.
	// term is different for each leadership, so a caller can see a new election.
	LeaderContext() (ctx context.Context, term uint64, isLeader bool)
}

var _ LeadershipGate = (*LeaderElector)(nil)

// LeaderElector holds the discovery lock so that one indexer replica at a time runs discovery.
type LeaderElector struct {
	locker            common.DiscoveryLocker
	leaseTimeout      time.Duration
	heartbeatInterval time.Duration
	acquireInterval   time.Duration
	lggr              logger.Logger
	metrics           common.IndexerMetricLabeler

	mu        sync.RWMutex
	leaderCtx context.Context
	term      uint64
	onElected []func(ctx context.Context)

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewLeaderElector(locker common.DiscoveryLocker, leaseTimeout, heartbeatInterval, acquireInterval time.Duration, lggr logger.Logger, metrics common.IndexerMetricLabeler) (*LeaderElector, error) {
	if locker == nil || lggr == nil || metrics == nil {
		return nil, errors.New("locker, logger and metrics must be specified")
	}
	if heartbeatInterval <= 0 || acquireInterval <= 0 || heartbeatInterval >= leaseTimeout {
		return nil, errors.New("heartbeat and acquire intervals must be positive, and heartbeat interval less than lease timeout")
	}
	return &LeaderElector{
		locker:            locker,
		leaseTimeout:      leaseTimeout,
		heartbeatInterval: heartbeatInterval,
		acquireInterval:   acquireInterval,
		lggr:              logger.Named(lggr, "LeaderElector"),
		metrics:           metrics,
	}, nil
}

// OnElected adds a callback that runs in its own goroutine each time this replica becomes leader.
// Call it before Start. The callback context is canceled when leadership is lost.
func (e *LeaderElector) OnElected(fn func(ctx context.Context)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onElected = append(e.onElected, fn)
}

// Start begins the election loop in a goroutine.
func (e *LeaderElector) Start(ctx context.Context) {
	ctx, e.cancel = context.WithCancel(ctx)
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
	return e.leaderCtx, e.term, e.leaderCtx != nil
}

// IsLeader reports if this replica is the discovery leader.
func (e *LeaderElector) IsLeader() bool {
	_, _, ok := e.LeaderContext()
	return ok
}

func (e *LeaderElector) run(ctx context.Context) {
	defer e.wg.Done()
	e.metrics.RecordDiscoveryLeaderGauge(ctx, false)
	for {
		if lease := e.tryAcquire(ctx); lease != nil {
			e.lead(ctx, lease)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.acquireInterval):
		}
	}
}

func (e *LeaderElector) tryAcquire(ctx context.Context) common.DiscoveryLease {
	acquireCtx, cancel := context.WithTimeout(ctx, e.acquireInterval)
	defer cancel()
	lease, acquired, err := e.locker.TryAcquireDiscoveryLock(acquireCtx, e.leaseTimeout)
	if err != nil {
		e.lggr.Warnw("Failed to try the discovery lock", "error", err)
		return nil
	}
	if !acquired {
		return nil
	}
	return lease
}

// lead runs while this replica holds the lease, and returns when a heartbeat fails or ctx is done.
func (e *LeaderElector) lead(ctx context.Context, lease common.DiscoveryLease) {
	leaderCtx, cancelLeader := context.WithCancel(ctx)
	e.mu.Lock()
	e.leaderCtx = leaderCtx //nolint:fatcontext // the elector gives the current leadership context to callers
	e.term++
	callbacks := append([]func(context.Context){}, e.onElected...)
	e.mu.Unlock()
	e.lggr.Infow("Elected discovery leader")
	e.metrics.RecordDiscoveryLeaderGauge(ctx, true)
	e.metrics.IncrementDiscoveryLeaderChanges(ctx)

	var callbacksWG sync.WaitGroup
	for _, fn := range callbacks {
		callbacksWG.Go(func() { fn(leaderCtx) })
	}

	e.heartbeat(leaderCtx, lease)

	e.mu.Lock()
	e.leaderCtx = nil
	e.mu.Unlock()
	cancelLeader()
	callbacksWG.Wait()
	lease.Release()
	e.lggr.Infow("Stopped being discovery leader")
	e.metrics.RecordDiscoveryLeaderGauge(context.WithoutCancel(ctx), false)
}

func (e *LeaderElector) heartbeat(leaderCtx context.Context, lease common.DiscoveryLease) {
	ticker := time.NewTicker(e.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-leaderCtx.Done():
			return
		case <-ticker.C:
			hbCtx, cancel := context.WithTimeout(leaderCtx, e.heartbeatInterval)
			err := lease.Heartbeat(hbCtx)
			cancel()
			if err != nil {
				e.lggr.Warnw("Discovery lock heartbeat failed, stopping leadership", "error", err)
				return
			}
		}
	}
}
