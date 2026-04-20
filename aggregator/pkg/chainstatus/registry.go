package chainstatus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// StatusMetrics is an optional dependency for recording chain-disabled metrics after each refresh.
type StatusMetrics interface {
	SetChainDisabledStatus(ctx context.Context, selector uint64, side LaneSide, disabled bool)
}

// Registry holds the in-memory set of disabled chains, refreshed periodically from the Store.
// It implements Checker.
type Registry struct {
	store           Store
	mu              sync.RWMutex
	disabledSources map[uint64]struct{}
	disabledDests   map[uint64]struct{}
	sourceSels      []uint64 // committee source selectors covered by metrics
	destSels        []uint64 // committee dest selectors covered by metrics
	statusMetrics   StatusMetrics
	lggr            logger.SugaredLogger
}

var _ Checker = (*Registry)(nil)

// RegistryOption configures optional Registry behavior.
type RegistryOption func(*Registry)

// WithStatusMetrics attaches a metrics reporter and the full set of committee selectors to
// the Registry. After each successful Refresh the gauge is emitted for every selector.
func WithStatusMetrics(m StatusMetrics, sourceSels, destSels []uint64) RegistryOption {
	return func(r *Registry) {
		r.statusMetrics = m
		r.sourceSels = sourceSels
		r.destSels = destSels
	}
}

// NewRegistry creates a registry backed by the given store. Call Refresh before use.
func NewRegistry(store Store, lggr logger.SugaredLogger, opts ...RegistryOption) *Registry {
	r := &Registry{
		store:           store,
		disabledSources: make(map[uint64]struct{}),
		disabledDests:   make(map[uint64]struct{}),
		lggr:            lggr,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Refresh reloads the disabled chain set from the store and emits status metrics when configured.
func (r *Registry) Refresh(ctx context.Context) error {
	statuses, err := r.store.ListDisabled(ctx)
	if err != nil {
		return fmt.Errorf("failed to list disabled chains: %w", err)
	}

	newSources := make(map[uint64]struct{}, len(statuses))
	newDests := make(map[uint64]struct{}, len(statuses))
	for _, s := range statuses {
		switch s.Side {
		case LaneSideSource:
			newSources[s.ChainSelector] = struct{}{}
		case LaneSideDestination:
			newDests[s.ChainSelector] = struct{}{}
		}
	}

	r.mu.Lock()
	r.disabledSources = newSources
	r.disabledDests = newDests
	r.mu.Unlock()

	if r.statusMetrics != nil {
		for _, sel := range r.sourceSels {
			_, disabled := newSources[sel]
			r.statusMetrics.SetChainDisabledStatus(ctx, sel, LaneSideSource, disabled)
		}
		for _, sel := range r.destSels {
			_, disabled := newDests[sel]
			r.statusMetrics.SetChainDisabledStatus(ctx, sel, LaneSideDestination, disabled)
		}
	}

	return nil
}

// IsDisabled returns true if either the source or destination chain in the report is disabled.
func (r *Registry) IsDisabled(report LaneReport) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.disabledSources[report.GetSourceChainSelector()]; ok {
		return true
	}
	_, ok := r.disabledDests[report.GetDestinationSelector()]
	return ok
}

// StartPeriodicRefresh runs Refresh on a ticker until ctx is canceled.
// Errors are logged but do not stop the refresh loop.
func (r *Registry) StartPeriodicRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.Refresh(ctx); err != nil {
					r.lggr.Errorw("Failed to refresh chain disable registry", "error", err)
				}
			}
		}
	}()
}
