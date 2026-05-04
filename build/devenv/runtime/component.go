package devenvruntime

import "context"

// Component is the base interface all components must implement.
type Component interface {
	ValidateConfig(componentConfig any) error
}

// ComponentFactory creates a component, optionally loading prior output for hot-reload.
// previousOutput is nil on first run.
type ComponentFactory func(previousOutput map[string]any) (Component, error)

// Phase1Component runs during Phase 1 (global services and prerequisites).
type Phase1Component interface {
	RunPhase1(ctx context.Context, globalConfig map[string]any, componentConfig any) (map[string]any, error)
}

// Phase2Component runs during Phase 2 (protocol platform deployments).
type Phase2Component interface {
	RunPhase2(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any) (map[string]any, error)
}

// Phase3Component runs during Phase 3 (CCVs and token pools).
type Phase3Component interface {
	RunPhase3(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any) (map[string]any, error)
}

// Phase4Component runs during Phase 4 (final configuration).
type Phase4Component interface {
	RunPhase4(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any) error
}
