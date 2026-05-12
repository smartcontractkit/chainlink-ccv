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
//
// Within a phase, every component (registered specifics and the fallback) sees
// a priorOutputs map cloned from the same phase-start snapshot. The snapshot
// is captured once before the phase begins, and each component receives its
// own clone so component-side mutation cannot leak to siblings. A component's
// own outputs are merged into the accumulated map *after* its callback
// returns, so they only become visible to components in later phases. This
// makes intra-phase ordering irrelevant from a data-visibility standpoint and
// forbids accidental sibling dependencies.
//
// Merging uses mergeNoOverwrite: a component that writes an output key already
// set (by a prior phase or by an earlier component in the same phase) causes
// the runtime to fail. Output keys behave as a write-once registry.
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

	// Phase 1 (no priorOutputs by interface; merge rules still apply).
	{
		const phase = 1
		for _, key := range sortedKeys(specific) {
			comp := specific[key]
			if p1, ok := comp.(Phase1Component); ok {
				out, err := p1.RunPhase1(ctx, rawConfig, rawConfig[key])
				if err != nil {
					return nil, fmt.Errorf("phase1 %s: %w", key, err)
				}
				if err := mergeNoOverwrite(accumulated, out, phase, key); err != nil {
					return nil, err
				}
			}
		}
		if p1, ok := fallback.(Phase1Component); ok {
			out, err := p1.RunPhase1(ctx, rawConfig, unclaimed)
			if err != nil {
				return nil, fmt.Errorf("phase1 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
		}
	}

	// Phase 2
	{
		const phase = 2
		phaseSnapshot := maps.Clone(accumulated)
		for _, key := range sortedKeys(specific) {
			comp := specific[key]
			if p2, ok := comp.(Phase2Component); ok {
				out, err := p2.RunPhase2(ctx, rawConfig, rawConfig[key], maps.Clone(phaseSnapshot))
				if err != nil {
					return nil, fmt.Errorf("phase2 %s: %w", key, err)
				}
				if err := mergeNoOverwrite(accumulated, out, phase, key); err != nil {
					return nil, err
				}
			}
		}
		if p2, ok := fallback.(Phase2Component); ok {
			out, err := p2.RunPhase2(ctx, rawConfig, unclaimed, maps.Clone(phaseSnapshot))
			if err != nil {
				return nil, fmt.Errorf("phase2 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
		}
	}

	// Phase 3
	{
		const phase = 3
		phaseSnapshot := maps.Clone(accumulated)
		for _, key := range sortedKeys(specific) {
			comp := specific[key]
			if p3, ok := comp.(Phase3Component); ok {
				out, err := p3.RunPhase3(ctx, rawConfig, rawConfig[key], maps.Clone(phaseSnapshot))
				if err != nil {
					return nil, fmt.Errorf("phase3 %s: %w", key, err)
				}
				if err := mergeNoOverwrite(accumulated, out, phase, key); err != nil {
					return nil, err
				}
			}
		}
		if p3, ok := fallback.(Phase3Component); ok {
			out, err := p3.RunPhase3(ctx, rawConfig, unclaimed, maps.Clone(phaseSnapshot))
			if err != nil {
				return nil, fmt.Errorf("phase3 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
		}
	}

	// Phase 4
	{
		const phase = 4
		phaseSnapshot := maps.Clone(accumulated)
		for _, key := range sortedKeys(specific) {
			comp := specific[key]
			if p4, ok := comp.(Phase4Component); ok {
				out, err := p4.RunPhase4(ctx, rawConfig, rawConfig[key], maps.Clone(phaseSnapshot))
				if err != nil {
					return nil, fmt.Errorf("phase4 %s: %w", key, err)
				}
				if err := mergeNoOverwrite(accumulated, out, phase, key); err != nil {
					return nil, err
				}
			}
		}
		if p4, ok := fallback.(Phase4Component); ok {
			out, err := p4.RunPhase4(ctx, rawConfig, unclaimed, maps.Clone(phaseSnapshot))
			if err != nil {
				return nil, fmt.Errorf("phase4 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
		}
	}

	return accumulated, nil
}

const fallbackOwner = "<fallback>"

// mergeNoOverwrite copies src into dst, returning an error if any key in src
// already exists in dst. The phase number and owner identify the offending
// component in the error message.
func mergeNoOverwrite(dst, src map[string]any, phase int, owner string) error {
	for k, v := range src {
		if _, exists := dst[k]; exists {
			return fmt.Errorf(
				"phase %d component %q wrote output key %q that is already set; "+
					"same-phase components must not collide and components must not "+
					"overwrite outputs from prior phases",
				phase, owner, k)
		}
		dst[k] = v
	}
	return nil
}

func sortedKeys(m map[string]Component) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
