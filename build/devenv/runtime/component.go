package devenvruntime

import (
	"context"
	"sync"
)

// Component is the base interface all components must implement.
type Component interface {
	ValidateConfig(componentConfig any) error
}

// ComponentFactory creates a component, optionally loading prior output for hot-reload.
// previousOutput is nil on first run.
type ComponentFactory func(previousOutput map[string]any) (Component, error)

// NetworkConfigFactory creates an empty chain-family-specific CCIP17Configuration object.
// NewEmpty returns any to avoid importing domain types into the runtime package;
// callers in package ccv type-assert the result to cciptestinterfaces.CCIP17Configuration.
type NetworkConfigFactory interface {
	NewEmpty() any
}

var (
	networkFactories   = map[string]NetworkConfigFactory{}
	networkFactoriesMu sync.Mutex
)

// RegisterNetworkFactory registers a factory for a chain family. Duplicate registrations are ignored.
func RegisterNetworkFactory(family string, f NetworkConfigFactory) {
	networkFactoriesMu.Lock()
	defer networkFactoriesMu.Unlock()
	if _, ok := networkFactories[family]; !ok {
		networkFactories[family] = f
	}
}

// GetNetworkFactory returns the registered factory for a chain family.
func GetNetworkFactory(family string) (NetworkConfigFactory, bool) {
	networkFactoriesMu.Lock()
	defer networkFactoriesMu.Unlock()
	f, ok := networkFactories[family]
	return f, ok
}

// Phase1Component runs during Phase 1 (global services and prerequisites).
type Phase1Component interface {
	RunPhase1(ctx context.Context, globalConfig map[string]any, componentConfig any) (map[string]any, error)
}

// Phase2Component runs during Phase 2 (protocol platform deployments).
// implMap maps blockchain container name to its empty CCIP17Configuration object,
// built by the runtime after Phase 1 using registered NetworkConfigFactory instances.
type Phase2Component interface {
	RunPhase2(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any, implMap map[string]any) (map[string]any, error)
}

// Phase3Component runs during Phase 3 (CCVs and token pools).
type Phase3Component interface {
	RunPhase3(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any, implMap map[string]any) (map[string]any, error)
}

// Phase4Component runs during Phase 4 (final configuration).
type Phase4Component interface {
	RunPhase4(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any, implMap map[string]any) error
}
