package devenvruntime

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"sort"

	"github.com/rs/zerolog"
)

// NewEnvironment runs the environment startup using the global registry.
func NewEnvironment(ctx context.Context, rawConfig map[string]any, logger zerolog.Logger) (map[string]any, error) {
	return NewEnvironmentWithRegistry(ctx, rawConfig, global, noopEffectExecutor{}, logger)
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
// When rawConfig[key] is a []any (TOML array-of-tables), the component is
// called once per element. Outputs from multiple instances are accumulated:
// same-type slice outputs are concatenated; any other collision is an error.
// After all instances of a component key finish, their combined output is
// merged into the accumulated map using write-once semantics (a key already
// set by a different component or prior phase still causes an error).
//
// After all components in a phase run, the runtime collects their Effect
// requests and executes them in a fixed order (CLNodeConfigEffect →
// FundingEffect → JobProposalEffect) before advancing to the next phase.
func NewEnvironmentWithRegistry(ctx context.Context, rawConfig map[string]any, r *Registry, effectExecutor EffectExecutor, logger zerolog.Logger) (map[string]any, error) {
	if effectExecutor == nil {
		effectExecutor = noopEffectExecutor{}
	}
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
		var phaseEffects []Effect
		for _, key := range sortedKeys(specific) {
			if _, present := rawConfig[key]; !present {
				continue
			}
			comp := specific[key]
			p1, ok := comp.(Phase1Component)
			if !ok {
				continue
			}
			elems := configElements(rawConfig[key])
			keyOutputs := map[string]any{}
			for i, elem := range elems {
				out, effects, err := p1.RunPhase1(ctx, rawConfig, elem)
				if err != nil {
					return nil, fmt.Errorf("phase1 %s: %w", phaseLabel(key, i, len(elems)), err)
				}
				if err := mergeAccumulate(keyOutputs, out); err != nil {
					return nil, fmt.Errorf("phase1 %s output collision: %w", phaseLabel(key, i, len(elems)), err)
				}
				phaseEffects = append(phaseEffects, effects...)
			}
			if err := mergeNoOverwrite(accumulated, keyOutputs, phase, key); err != nil {
				return nil, err
			}
		}
		if p1, ok := fallback.(Phase1Component); ok {
			out, effects, err := p1.RunPhase1(ctx, rawConfig, unclaimed)
			if err != nil {
				return nil, fmt.Errorf("phase1 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
			phaseEffects = append(phaseEffects, effects...)
		}
		if err := effectExecutor.Execute(ctx, phaseEffects, accumulated); err != nil {
			return nil, fmt.Errorf("phase1 effects: %w", err)
		}
	}

	// Phase 2
	{
		const phase = 2
		phaseSnapshot := maps.Clone(accumulated)
		var phaseEffects []Effect
		for _, key := range sortedKeys(specific) {
			if _, present := rawConfig[key]; !present {
				continue
			}
			comp := specific[key]
			p2, ok := comp.(Phase2Component)
			if !ok {
				continue
			}
			elems := configElements(rawConfig[key])
			keyOutputs := map[string]any{}
			for i, elem := range elems {
				out, effects, err := p2.RunPhase2(ctx, rawConfig, elem, maps.Clone(phaseSnapshot))
				if err != nil {
					return nil, fmt.Errorf("phase2 %s: %w", phaseLabel(key, i, len(elems)), err)
				}
				if err := mergeAccumulate(keyOutputs, out); err != nil {
					return nil, fmt.Errorf("phase2 %s output collision: %w", phaseLabel(key, i, len(elems)), err)
				}
				phaseEffects = append(phaseEffects, effects...)
			}
			if err := mergeNoOverwrite(accumulated, keyOutputs, phase, key); err != nil {
				return nil, err
			}
		}
		if p2, ok := fallback.(Phase2Component); ok {
			out, effects, err := p2.RunPhase2(ctx, rawConfig, unclaimed, maps.Clone(phaseSnapshot))
			if err != nil {
				return nil, fmt.Errorf("phase2 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
			phaseEffects = append(phaseEffects, effects...)
		}
		if err := effectExecutor.Execute(ctx, phaseEffects, accumulated); err != nil {
			return nil, fmt.Errorf("phase2 effects: %w", err)
		}
	}

	// Phase 3
	{
		const phase = 3
		phaseSnapshot := maps.Clone(accumulated)
		var phaseEffects []Effect
		for _, key := range sortedKeys(specific) {
			if _, present := rawConfig[key]; !present {
				continue
			}
			comp := specific[key]
			p3, ok := comp.(Phase3Component)
			if !ok {
				continue
			}
			elems := configElements(rawConfig[key])
			keyOutputs := map[string]any{}
			for i, elem := range elems {
				out, effects, err := p3.RunPhase3(ctx, rawConfig, elem, maps.Clone(phaseSnapshot))
				if err != nil {
					return nil, fmt.Errorf("phase3 %s: %w", phaseLabel(key, i, len(elems)), err)
				}
				if err := mergeAccumulate(keyOutputs, out); err != nil {
					return nil, fmt.Errorf("phase3 %s output collision: %w", phaseLabel(key, i, len(elems)), err)
				}
				phaseEffects = append(phaseEffects, effects...)
			}
			if err := mergeNoOverwrite(accumulated, keyOutputs, phase, key); err != nil {
				return nil, err
			}
		}
		if p3, ok := fallback.(Phase3Component); ok {
			out, effects, err := p3.RunPhase3(ctx, rawConfig, unclaimed, maps.Clone(phaseSnapshot))
			if err != nil {
				return nil, fmt.Errorf("phase3 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
			phaseEffects = append(phaseEffects, effects...)
		}
		if err := effectExecutor.Execute(ctx, phaseEffects, accumulated); err != nil {
			return nil, fmt.Errorf("phase3 effects: %w", err)
		}
	}

	// Phase 4
	{
		const phase = 4
		phaseSnapshot := maps.Clone(accumulated)
		var phaseEffects []Effect
		for _, key := range sortedKeys(specific) {
			if _, present := rawConfig[key]; !present {
				continue
			}
			comp := specific[key]
			p4, ok := comp.(Phase4Component)
			if !ok {
				continue
			}
			elems := configElements(rawConfig[key])
			keyOutputs := map[string]any{}
			for i, elem := range elems {
				out, effects, err := p4.RunPhase4(ctx, rawConfig, elem, maps.Clone(phaseSnapshot))
				if err != nil {
					return nil, fmt.Errorf("phase4 %s: %w", phaseLabel(key, i, len(elems)), err)
				}
				if err := mergeAccumulate(keyOutputs, out); err != nil {
					return nil, fmt.Errorf("phase4 %s output collision: %w", phaseLabel(key, i, len(elems)), err)
				}
				phaseEffects = append(phaseEffects, effects...)
			}
			if err := mergeNoOverwrite(accumulated, keyOutputs, phase, key); err != nil {
				return nil, err
			}
		}
		if p4, ok := fallback.(Phase4Component); ok {
			out, effects, err := p4.RunPhase4(ctx, rawConfig, unclaimed, maps.Clone(phaseSnapshot))
			if err != nil {
				return nil, fmt.Errorf("phase4 fallback: %w", err)
			}
			if err := mergeNoOverwrite(accumulated, out, phase, fallbackOwner); err != nil {
				return nil, err
			}
			phaseEffects = append(phaseEffects, effects...)
		}
		if err := effectExecutor.Execute(ctx, phaseEffects, accumulated); err != nil {
			return nil, fmt.Errorf("phase4 effects: %w", err)
		}
	}

	return accumulated, nil
}

const fallbackOwner = "<fallback>"

// configElements returns rawVal as []any when it is already a slice (TOML
// array-of-tables), or wraps a scalar value in a single-element slice (TOML
// table). This lets phase loops treat both cases uniformly: each component is
// called exactly once per element.
func configElements(rawVal any) []any {
	if arr, ok := rawVal.([]any); ok {
		return arr
	}
	return []any{rawVal}
}

// phaseLabel returns "key" for single-element configs and "key[i]" for
// multi-element configs, so error messages stay clean for the common case.
func phaseLabel(key string, i, total int) string {
	if total > 1 {
		return fmt.Sprintf("%s[%d]", key, i)
	}
	return key
}

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

// mergeAccumulate copies src into dst. When a key already exists in dst and
// both the existing and new values are slices of the same element type, the
// slices are concatenated. Any other collision (both scalars, or type
// mismatch) returns an error.
func mergeAccumulate(dst, src map[string]any) error {
	for k, v := range src {
		existing, exists := dst[k]
		if !exists {
			dst[k] = v
			continue
		}
		merged, err := appendSlice(existing, v)
		if err != nil {
			return fmt.Errorf("output key %q: %w", k, err)
		}
		dst[k] = merged
	}
	return nil
}

// appendSlice concatenates two slice values of the same element type using
// reflection. Returns an error if either value is not a slice or if their
// types differ.
func appendSlice(a, b any) (any, error) {
	va := reflect.ValueOf(a)
	vb := reflect.ValueOf(b)
	if va.Kind() != reflect.Slice {
		return nil, fmt.Errorf("cannot accumulate: existing value %T is not a slice", a)
	}
	if vb.Kind() != reflect.Slice {
		return nil, fmt.Errorf("cannot accumulate: new value %T is not a slice", b)
	}
	if va.Type() != vb.Type() {
		return nil, fmt.Errorf("type mismatch: cannot concatenate %T and %T", a, b)
	}
	return reflect.AppendSlice(va, vb).Interface(), nil
}

func sortedKeys(m map[string]Component) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
