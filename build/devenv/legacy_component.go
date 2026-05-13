package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
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

// RunPhase3 invokes the forked monolith runPhasedEnvironment after splicing
// the blockchain inputs deployed in Phase 1 and the CL node sets created in
// Phase 2 into the loaded *Cfg. The legacy fallback runs in Phase 3 because
// the runtime captures each phase's snapshot once at the start of the phase
// — Phase 2 components' outputs are only visible to Phase 3 callers. As
// components are extracted, the body of runPhasedEnvironment will continue
// to shrink.
func (l *legacyComponent) RunPhase3(
	ctx context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err := Load[Cfg](configs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	bcs, ok := priorOutputs["blockchains"].([]*blockchain.Input)
	if !ok {
		return nil, nil, fmt.Errorf("phase 1 did not produce []*blockchain.Input under \"blockchains\"")
	}
	in.Blockchains = bcs

	// nodesets are optional: env.toml may omit [[nodesets]] entirely, in which
	// case the chainlinknode component is dormant and produces no output.
	if nss, ok := priorOutputs["nodesets"].([]*ns.Input); ok {
		in.NodeSets = nss
	}

	cfg, err := runPhasedEnvironment(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, nil, nil
}
