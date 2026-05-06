package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// legacyCfgKey is the output map key under which the legacy component stores
// the fully-initialized *Cfg so that NewEnvironmentPhased() can extract it.
const legacyCfgKey = "_legacy_cfg"

func init() {
	devenvruntime.SetFallback(legacyFactory)
}

func legacyFactory(_ map[string]any) (devenvruntime.Component, error) {
	return &legacyComponent{}, nil
}

type legacyComponent struct{}

func (l *legacyComponent) ValidateConfig(_ any) error { return nil }

// RunPhase2 runs the environment startup after blockchain networks have been
// deployed in Phase 1. It reads the pre-populated []*blockchain.Input from
// priorOutputs and injects them into the loaded config before calling
// runPhasedEnvironment.
func (l *legacyComponent) RunPhase2(ctx context.Context, _ map[string]any, _ any, priorOutputs map[string]any, implMap map[string]cciptestinterfaces.CCIP17Configuration) (map[string]any, error) {
	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err := Load[Cfg](configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Inject blockchains that were deployed in Phase 1.
	if bcs, ok := priorOutputs["blockchains"].([]*blockchain.Input); ok {
		in.Blockchains = bcs
	}

	cfg, err := runPhasedEnvironment(ctx, in, priorOutputs, implMap)
	if err != nil {
		return nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, nil
}
