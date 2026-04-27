package messagedisablement

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Metrics interface {
	SetMessageDisablementRuleActive(ctx context.Context, active int64, keyValues ...string)
	SetMessageDisablementRulesRefreshFailure(ctx context.Context, failed int64)
}

type noopMetrics struct{}

func (noopMetrics) SetMessageDisablementRuleActive(context.Context, int64, ...string) {}
func (noopMetrics) SetMessageDisablementRulesRefreshFailure(context.Context, int64)   {}

type RegistryOption func(*Registry)

func WithMetrics(metrics Metrics) RegistryOption {
	return func(r *Registry) {
		if metrics != nil {
			r.metrics = metrics
		}
	}
}

type Registry struct {
	store                  Store
	metrics                Metrics
	mu                     sync.RWMutex
	activeRules            []activeRule
	activeRuleMetricLabels map[string][]string
	lggr                   logger.SugaredLogger
}

var _ Checker = (*Registry)(nil)

func NewRegistry(store Store, lggr logger.SugaredLogger, opts ...RegistryOption) *Registry {
	r := &Registry{
		store:                  store,
		metrics:                noopMetrics{},
		activeRuleMetricLabels: make(map[string][]string),
		lggr:                   lggr,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Registry) Refresh(ctx context.Context) error {
	rules, err := r.store.List(ctx, nil)
	if err != nil {
		r.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 1)
		r.lggr.Errorw("Failed to list message disablement rules for registry refresh",
			"error", err,
			"active_rule_count", r.ActiveRuleCount(),
		)
		return fmt.Errorf("failed to list message disablement rules: %w", err)
	}

	compiled, err := compileRules(rules)
	if err != nil {
		r.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 1)
		r.lggr.Errorw("Failed to compile message disablement rules for registry refresh",
			"error", err,
			"loaded_rule_count", len(rules),
			"active_rule_count", r.ActiveRuleCount(),
		)
		return err
	}

	r.mu.Lock()
	previousMetricLabels := r.activeRuleMetricLabels
	r.activeRules = compiled.rules
	r.activeRuleMetricLabels = compiled.metricLabels
	r.mu.Unlock()

	r.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 0)
	r.emitActiveRuleMetrics(ctx, previousMetricLabels, compiled.metricLabels)
	r.lggr.Infow("Refreshed message disablement rules registry",
		"rule_count", len(compiled.rules),
		"chain_rules", compiled.chainCount,
		"lane_rules", compiled.laneCount,
		"token_rules", compiled.tokenCount,
	)

	return nil
}

func (r *Registry) IsDisabled(report MessageReport) bool {
	if report == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rule := range r.activeRules {
		if rule.IsDisabled(report) {
			return true
		}
	}
	return false
}

func (r *Registry) StartPeriodicRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		r.lggr.Warnw("Message disablement rules refresh interval must be positive; using default", "configured_interval", interval, "default_interval", time.Minute)
		interval = time.Minute
	}
	r.lggr.Infow("Starting periodic message disablement rules refresh", "interval", interval.String())
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				r.lggr.Infow("Stopping periodic message disablement rules refresh", "error", ctx.Err())
				return
			case <-ticker.C:
				if err := r.Refresh(ctx); err != nil {
					r.lggr.Errorw("Failed to refresh message disablement rules registry; keeping previously active rules",
						"error", err,
						"active_rule_count", r.ActiveRuleCount(),
					)
				}
			}
		}
	}()
}

func (r *Registry) ActiveRuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.activeRules)
}

func (r *Registry) emitActiveRuleMetrics(ctx context.Context, previous, current map[string][]string) {
	for key, labels := range previous {
		if _, stillActive := current[key]; !stillActive {
			r.metrics.SetMessageDisablementRuleActive(ctx, 0, labels...)
		}
	}
	for _, labels := range current {
		r.metrics.SetMessageDisablementRuleActive(ctx, 1, labels...)
	}
}

type compiledRules struct {
	rules        []activeRule
	metricLabels map[string][]string
	chainCount   int
	laneCount    int
	tokenCount   int
}

func compileRules(rules []Rule) (compiledRules, error) {
	compiled := compiledRules{
		rules:        make([]activeRule, 0, len(rules)),
		metricLabels: make(map[string][]string, len(rules)),
	}

	for _, rule := range rules {
		normalized, err := NormalizeRuleData(rule.Type, rule.Data)
		if err != nil {
			return compiledRules{}, fmt.Errorf("invalid message disablement rule %s: %w", rule.ID, err)
		}
		rule.Data = normalized

		var active activeRule
		switch rule.Type {
		case RuleTypeChain:
			active, err = newChainActiveRule(rule)
			if err != nil {
				return compiledRules{}, fmt.Errorf("invalid Chain rule %s: %w", rule.ID, err)
			}
			compiled.chainCount++
		case RuleTypeLane:
			active, err = newLaneActiveRule(rule)
			if err != nil {
				return compiledRules{}, fmt.Errorf("invalid Lane rule %s: %w", rule.ID, err)
			}
			compiled.laneCount++
		case RuleTypeToken:
			active, err = newTokenActiveRule(rule)
			if err != nil {
				return compiledRules{}, fmt.Errorf("invalid Token rule %s: %w", rule.ID, err)
			}
			compiled.tokenCount++
		default:
			return compiledRules{}, fmt.Errorf("unknown rule type %q for rule %s", rule.Type, rule.ID)
		}
		compiled.rules = append(compiled.rules, active)
		compiled.metricLabels[active.metricKey()] = active.metricLabels()
	}

	return compiled, nil
}
