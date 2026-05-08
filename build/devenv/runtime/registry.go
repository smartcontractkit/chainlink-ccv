package devenvruntime

import (
	"fmt"
	"maps"
)

// Registry maps top-level config keys to component factories.
type Registry struct {
	factories map[string]ComponentFactory
	fallback  ComponentFactory
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]ComponentFactory)}
}

// Register associates a top-level config key with a factory.
// Returns an error if a component is already registered for that key.
func (r *Registry) Register(configKey string, fac ComponentFactory) error {
	if _, exists := r.factories[configKey]; exists {
		return fmt.Errorf("component already registered for key %q", configKey)
	}
	r.factories[configKey] = fac
	return nil
}

// SetFallback registers a catch-all factory for config keys not claimed by any registered component.
// The fallback component receives only unclaimed keys as its componentConfig.
func (r *Registry) SetFallback(fac ComponentFactory) {
	r.fallback = fac
}

// instantiate creates all components for the given raw config.
// Returns specific components (keyed by config key) and the fallback component (nil if none registered).
func (r *Registry) instantiate(previousOutput map[string]any) (map[string]Component, Component, error) {
	specific := make(map[string]Component, len(r.factories))
	for key, fac := range r.factories {
		comp, err := fac(previousOutput)
		if err != nil {
			return nil, nil, fmt.Errorf("creating component %q: %w", key, err)
		}
		specific[key] = comp
	}

	var fallbackComp Component
	if r.fallback != nil {
		comp, err := r.fallback(previousOutput)
		if err != nil {
			return nil, nil, fmt.Errorf("creating fallback component: %w", err)
		}
		fallbackComp = comp
	}

	return specific, fallbackComp, nil
}

// validate calls ValidateConfig on all instantiated components.
func (r *Registry) validate(rawConfig map[string]any, specific map[string]Component, fallback Component) error {
	for key, comp := range specific {
		if err := comp.ValidateConfig(rawConfig[key]); err != nil {
			return fmt.Errorf("component %q config invalid: %w", key, err)
		}
	}
	if fallback != nil {
		unclaimed := unclaimedKeys(rawConfig, r.factories)
		if err := fallback.ValidateConfig(unclaimed); err != nil {
			return fmt.Errorf("fallback component config invalid: %w", err)
		}
	}
	return nil
}

// unclaimedKeys returns the entries from rawConfig that no registered factory claims.
func unclaimedKeys(rawConfig map[string]any, factories map[string]ComponentFactory) map[string]any {
	unclaimed := maps.Clone(rawConfig)
	for key := range factories {
		delete(unclaimed, key)
	}
	return unclaimed
}

// global is the package-level registry populated by component func init() calls.
var global = NewRegistry()

// Register adds a component to the global registry.
func Register(configKey string, fac ComponentFactory) error {
	return global.Register(configKey, fac)
}

// SetFallback sets the fallback component on the global registry.
func SetFallback(fac ComponentFactory) {
	global.SetFallback(fac)
}
