package devenvruntime

import (
	"context"
)

// Component is the base interface all components must implement.
type Component interface {
	ValidateConfig(componentConfig any) error
}

// ComponentFactory creates a component, optionally loading prior output for hot-reload.
// previousOutput is nil on first run.
type ComponentFactory func(previousOutput map[string]any) (Component, error)

// BuiltinComponent runs in a fixed order before any Phase1-4 components.
// Builtins represent infrastructure that subsequent components depend on
// (blockchains, CL nodes, JD). Each builtin sees the outputs of all
// previously-run builtins via priorOutputs.
//
// The execution order is set by builtinOrder in environment.go. A future
// refactor can replace that hardcoded list with a topological sort over
// a DependsOn() method without changing this interface.
type BuiltinComponent interface {
	RunBuiltin(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any) (map[string]any, error)
}

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
	RunPhase4(ctx context.Context, globalConfig map[string]any, componentConfig any, priorOutputs map[string]any) (map[string]any, error)
}
