package ccv

import (
	"context"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
)

// legacyCfgKey is the output map key under which the legacy fallback component
// stores the fully-initialized *Cfg so that NewPhasedEnvironment can extract it.
const legacyCfgKey = "_legacy_cfg"

func init() {
	devenvruntime.SetFallback(legacyFactory)
}

func legacyFactory(_ map[string]any) (devenvruntime.Component, error) {
	return &legacyComponent{}, nil
}

type legacyComponent struct{}

func (l *legacyComponent) ValidateConfig(_ any) error { return nil }

// RunPhase2 invokes the forked monolith runPhasedEnvironment. It is registered
// as the runtime's fallback so that any config keys not claimed by a specific
// component are funneled through here. As components are extracted, the body of
// runPhasedEnvironment will shrink.
func (l *legacyComponent) RunPhase2(
	ctx context.Context,
	_ map[string]any,
	_ any,
	_ map[string]any,
) (map[string]any, error) {
	cfg, err := runPhasedEnvironment(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, nil
}
