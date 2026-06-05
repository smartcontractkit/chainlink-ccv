package devenvruntime

import (
	"fmt"
	"maps"
)

// Registry maps top-level config keys to component factories.
type Registry struct {
	factories map[string]ComponentFactory
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

// instantiate creates all components for the given raw config.
func (r *Registry) instantiate(previousOutput map[string]any) (map[string]Component, error) {
	specific := make(map[string]Component, len(r.factories))
	for key, fac := range r.factories {
		comp, err := fac(previousOutput)
		if err != nil {
			return nil, fmt.Errorf("creating component %q: %w", key, err)
		}
		specific[key] = comp
	}
	return specific, nil
}

// validate calls ValidateConfig on all instantiated components whose
// top-level config key is present in rawConfig. Components whose key is
// unset are dormant — neither validated nor phase-executed — so registered
// components can sit out runs that don't configure them.
func (r *Registry) validate(rawConfig map[string]any, specific map[string]Component) error {
	for key, comp := range specific {
		if _, ok := rawConfig[key]; !ok {
			continue
		}
		if err := comp.ValidateConfig(rawConfig[key]); err != nil {
			return fmt.Errorf("component %q config invalid: %w", key, err)
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

// GlobalRegistry returns the package-level registry populated by component init() calls.
func GlobalRegistry() *Registry {
	return global
}
