package ccv

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
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

// RunPhase4 invokes the forked monolith runPhasedEnvironment after splicing
// the blockchain inputs deployed in Phase 1, the CL node sets created in
// Phase 2, and any standalone executors launched in Phase 3 into the loaded
// *Cfg. The legacy fallback runs in Phase 4 so that Phase 3 specific
// components (executor) can complete before the monolith runs contract
// deployment, job spec generation, funding, and job proposal. As components
// are extracted, the body of runPhasedEnvironment will continue to shrink.
func (l *legacyComponent) RunPhase4(
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

	// jd is optional: env.toml may omit [jd] entirely. When present, the JD
	// component starts the container in Phase 2 so runPhasedEnvironment can
	// skip the StartJDInfrastructure call and proceed directly to node
	// registration and chain-config wiring.
	if jdInfra, ok := priorOutputs["jd"].(*jobs.JDInfrastructure); ok {
		in.JDInfra = jdInfra
	}

	// executor is optional: env.toml may omit [[executor]] entirely. When
	// present, the executor component launches containers and registers with JD
	// in Phase 3; the monolith skips launch/registration and proceeds directly
	// to job spec generation, funding, and job proposal.
	if execs, ok := priorOutputs["executor"].([]*executorsvc.Input); ok {
		in.Executor = execs
	}

	// fake is optional: env.toml may omit [fake] entirely. When present, the
	// fake component starts the container in Phase 1; the monolith reads the
	// output to wire attestation API endpoints into token verifier configs.
	if fake, ok := priorOutputs["fake"].(*services.FakeInput); ok {
		in.Fake = fake
	}

	// pricer is optional: env.toml may omit [pricer] entirely. When present,
	// the pricer component starts the container and funds its key in Phase 3.
	if pricer, ok := priorOutputs["pricer"].(*services.PricerInput); ok {
		in.Pricer = pricer
	}

	cfg, phaseEffects, err := runPhasedEnvironment(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, phaseEffects, nil
}
