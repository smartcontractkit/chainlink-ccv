package messagerules

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	shared "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Metrics interface {
	// SetMessageDisablementRuleActive records whether a disablement rule is active.
	SetMessageDisablementRuleActive(ctx context.Context, active int64, keyValues ...string)
	// SetMessageDisablementRulesRefreshFailure records whether the latest registry refresh failed.
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
	store                  shared.Store
	metrics                Metrics
	mu                     sync.RWMutex
	activeRules            shared.CompiledRules
	activeRuleMetricLabels map[string][]string
	lggr                   logger.SugaredLogger
	ready                  bool
}

var _ shared.Checker = (*Registry)(nil)

func NewRegistry(store shared.Store, lggr logger.SugaredLogger, opts ...RegistryOption) *Registry {
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

	compiled, err := shared.CompileRules(rules)
	if err != nil {
		r.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 1)
		r.lggr.Errorw("Failed to compile message disablement rules for registry refresh",
			"error", err,
			"loaded_rule_count", len(rules),
			"active_rule_count", r.ActiveRuleCount(),
		)
		return err
	}

	metricLabels := metricLabelsForRules(compiled.RulesSnapshot())

	r.mu.Lock()
	previousMetricLabels := r.activeRuleMetricLabels
	r.activeRules = compiled
	r.activeRuleMetricLabels = metricLabels
	r.ready = true
	r.mu.Unlock()

	r.metrics.SetMessageDisablementRulesRefreshFailure(ctx, 0)
	r.emitActiveRuleMetrics(ctx, previousMetricLabels, metricLabels)
	r.lggr.Infow("Refreshed message disablement rules registry",
		"rule_count", compiled.ActiveRuleCount(),
	)

	return nil
}

func (r *Registry) IsDisabled(report shared.MessageReport) bool {
	if report == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.activeRules.IsDisabled(report)
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
	return r.activeRules.ActiveRuleCount()
}

func (r *Registry) ActiveRulesSnapshot() ([]shared.Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeRules.RulesSnapshot(), r.ready
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

func metricLabelsForRules(rules []shared.Rule) map[string][]string {
	ruleMetricKey := func(rule shared.Rule) (string, error) {
		ruleType, data, err := shared.EncodeRuleData(rule.Data)
		if err != nil {
			return "", err
		}
		return ruleTypeMetricValue(ruleType) + "|" + string(data), nil
	}

	labels := make(map[string][]string, len(rules))
	for _, rule := range rules {
		key, err := ruleMetricKey(rule)
		if err != nil {
			continue
		}
		labels[key] = ruleMetricLabels(rule)
	}
	return labels
}

func ruleMetricLabels(rule shared.Rule) []string {
	labels := []string{
		"rule_type", ruleTypeMetricValue(rule.Type),
	}

	switch rule.Type {
	case shared.RuleTypeChain:
		data, err := rule.ChainData()
		if err == nil {
			labels = append(labels, "chain_selector", strconv.FormatUint(data.ChainSelector, 10))
		}
	case shared.RuleTypeLane:
		data, err := rule.LaneData()
		if err == nil {
			labels = append(labels,
				"selector_a", strconv.FormatUint(data.SelectorA, 10),
				"selector_b", strconv.FormatUint(data.SelectorB, 10),
			)
		}
	case shared.RuleTypeToken:
		data, err := rule.TokenData()
		if err == nil {
			labels = append(labels,
				"chain_selector", strconv.FormatUint(data.ChainSelector, 10),
				"token_address", data.TokenAddress,
			)
		}
	}
	return labels
}

func ruleTypeMetricValue(ruleType shared.RuleType) string {
	return strings.ToLower(string(ruleType))
}
