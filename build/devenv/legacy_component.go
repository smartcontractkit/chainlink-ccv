package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
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

// RunPhase2 invokes the forked monolith runPhasedEnvironment after splicing the
// blockchain inputs deployed in Phase 1 into the loaded *Cfg. As components are
// extracted, the body of runPhasedEnvironment will continue to shrink.
func (l *legacyComponent) RunPhase2(
	ctx context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, error) {
	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err := Load[Cfg](configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	bcs, ok := priorOutputs["blockchains"].([]*blockchain.Input)
	if !ok {
		return nil, fmt.Errorf("phase 1 did not produce []*blockchain.Input under \"blockchains\"")
	}
	in.Blockchains = bcs

	cfg, err := runPhasedEnvironment(ctx, in)
	if err != nil {
		return nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, nil
}
