package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
)

// legacyCfgKey is the output map key under which the legacy component stores
// the fully-initialized *Cfg so that NewEnvironment() can extract it.
const legacyCfgKey = "_legacy_cfg"

func init() {
	devenvruntime.SetFallback(legacyFactory)
}

func legacyFactory(_ map[string]any) (devenvruntime.Component, error) {
	return &legacyComponent{}, nil
}

type legacyComponent struct{}

func (l *legacyComponent) ValidateConfig(_ any) error { return nil }

// RunPhase1 runs the entire environment startup. All phases are collapsed into
// Phase 1 until individual components are extracted in later PRs.
func (l *legacyComponent) RunPhase1(ctx context.Context, _ map[string]any, _ any) (map[string]any, error) {
	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err := Load[Cfg](configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	cfg, err := runLegacyEnvironment(ctx, in)
	if err != nil {
		return nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, nil
}
