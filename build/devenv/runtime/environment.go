package devenvruntime

import (
	"context"
	"fmt"
	"maps"
	"sort"

	"github.com/rs/zerolog"
)

// NewEnvironment runs the environment startup using the global registry.
func NewEnvironment(ctx context.Context, rawConfig map[string]any, logger zerolog.Logger) (map[string]any, error) {
	return NewEnvironmentWithRegistry(ctx, rawConfig, global, logger)
}

// NewEnvironmentWithRegistry runs the environment startup using the provided registry.
// This variant is used by tests that need an explicit registry.
func NewEnvironmentWithRegistry(ctx context.Context, rawConfig map[string]any, r *Registry, logger zerolog.Logger) (map[string]any, error) {
	specific, fallback, err := r.instantiate(nil)
	if err != nil {
		return nil, err
	}
	if err := r.validate(rawConfig, specific, fallback); err != nil {
		return nil, err
	}

	// The fallback component receives all config keys not claimed by a specific
	// registered component, rather than a single top-level key slice.
	unclaimed := unclaimedKeys(rawConfig, r.factories)
	if len(unclaimed) > 0 && fallback == nil {
		keys := make([]string, 0, len(unclaimed))
		for k := range unclaimed {
			keys = append(keys, k)
		}
		logger.Error().Strs("keys", keys).Msg("unclaimed config keys with no fallback component registered")
	}
	accumulated := map[string]any{}

	// Phase 1
	for _, key := range sortedKeys(specific) {
		comp := specific[key]
		if p1, ok := comp.(Phase1Component); ok {
			out, err := p1.RunPhase1(ctx, rawConfig, rawConfig[key])
			if err != nil {
				return nil, fmt.Errorf("phase1 %s: %w", key, err)
			}
			maps.Copy(accumulated, out)
		}
	}
	if fallback != nil {
		if p1, ok := fallback.(Phase1Component); ok {
			out, err := p1.RunPhase1(ctx, rawConfig, unclaimed)
			if err != nil {
				return nil, fmt.Errorf("phase1 fallback: %w", err)
			}
			maps.Copy(accumulated, out)
		}
	}

	// Phase 2
	for _, key := range sortedKeys(specific) {
		comp := specific[key]
		if p2, ok := comp.(Phase2Component); ok {
			out, err := p2.RunPhase2(ctx, rawConfig, rawConfig[key], maps.Clone(accumulated))
			if err != nil {
				return nil, fmt.Errorf("phase2 %s: %w", key, err)
			}
			maps.Copy(accumulated, out)
		}
	}
	if fallback != nil {
		if p2, ok := fallback.(Phase2Component); ok {
			out, err := p2.RunPhase2(ctx, rawConfig, unclaimed, maps.Clone(accumulated))
			if err != nil {
				return nil, fmt.Errorf("phase2 fallback: %w", err)
			}
			maps.Copy(accumulated, out)
		}
	}

	// Phase 3
	for _, key := range sortedKeys(specific) {
		comp := specific[key]
		if p3, ok := comp.(Phase3Component); ok {
			out, err := p3.RunPhase3(ctx, rawConfig, rawConfig[key], maps.Clone(accumulated))
			if err != nil {
				return nil, fmt.Errorf("phase3 %s: %w", key, err)
			}
			maps.Copy(accumulated, out)
		}
	}
	if fallback != nil {
		if p3, ok := fallback.(Phase3Component); ok {
			out, err := p3.RunPhase3(ctx, rawConfig, unclaimed, maps.Clone(accumulated))
			if err != nil {
				return nil, fmt.Errorf("phase3 fallback: %w", err)
			}
			maps.Copy(accumulated, out)
		}
	}

	// Phase 4
	for _, key := range sortedKeys(specific) {
		comp := specific[key]
		if p4, ok := comp.(Phase4Component); ok {
			if err := p4.RunPhase4(ctx, rawConfig, rawConfig[key], maps.Clone(accumulated)); err != nil {
				return nil, fmt.Errorf("phase4 %s: %w", key, err)
			}
		}
	}
	if fallback != nil {
		if p4, ok := fallback.(Phase4Component); ok {
			if err := p4.RunPhase4(ctx, rawConfig, unclaimed, maps.Clone(accumulated)); err != nil {
				return nil, fmt.Errorf("phase4 fallback: %w", err)
			}
		}
	}

	return accumulated, nil
}

func sortedKeys(m map[string]Component) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
