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

// legacySetupKey is the output map key under which RunPhase3 stores the
// *phasedSetup so that RunPhase4 can call runPhasedEnvironmentFinish.
const legacySetupKey = "_legacy_setup"

// preparedIndexerInputsKey is the output map key under which RunPhase3 stores
// the slice of fully-prepared *services.IndexerInput pointers so that the
// indexer Phase 4 component can call services.NewIndexer for each one without
// importing the parent ccv package.
const preparedIndexerInputsKey = "_prepared_indexer_inputs"

func init() {
	devenvruntime.SetFallback(legacyFactory)
}

func legacyFactory(_ map[string]any) (devenvruntime.Component, error) {
	return &legacyComponent{}, nil
}

type legacyComponent struct{}

func (l *legacyComponent) ValidateConfig(_ any) error { return nil }

// RunPhase3 loads the TOML config, splices in the Phase 1/2/3 outputs produced
// by dedicated components (blockchains, nodesets, jd, executor, fake, pricer),
// and calls runPhasedEnvironmentSetup. The resulting *phasedSetup (under
// legacySetupKey) and the fully-prepared []*services.IndexerInput (under
// preparedIndexerInputsKey) are passed forward so that the indexer Phase 4
// component can launch indexer containers and RunPhase4 can complete wiring.
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

	if nss, ok := priorOutputs["nodesets"].([]*ns.Input); ok {
		in.NodeSets = nss
	}

	if jdInfra, ok := priorOutputs["jd"].(*jobs.JDInfrastructure); ok {
		in.JDInfra = jdInfra
	}

	if execs, ok := priorOutputs["executor"].([]*executorsvc.Input); ok {
		in.Executor = execs
	}

	if fake, ok := priorOutputs["fake"].(*services.FakeInput); ok {
		in.Fake = fake
	}

	if pricer, ok := priorOutputs["pricer"].(*services.PricerInput); ok {
		in.Pricer = pricer
	}

	setup, err := runPhasedEnvironmentSetup(ctx, in)
	if err != nil {
		return nil, nil, err
	}

	return map[string]any{
		legacySetupKey:           setup,
		preparedIndexerInputsKey: setup.In.Indexer,
		"aggregators":            setup.In.Aggregator,
		"shared_tls_certs":       setup.SharedTLSCerts,
	}, nil, nil
}

// RunPhase4 reads the *phasedSetup produced by RunPhase3 (after the indexer
// Phase 4 component has called services.NewIndexer for each prepared input,
// mutating idxIn.Out on the shared pointers), then calls
// runPhasedEnvironmentFinish to complete contract deployment, job spec
// generation, funding, and job proposal.
func (l *legacyComponent) RunPhase4(
	ctx context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	setup, ok := priorOutputs[legacySetupKey].(*phasedSetup)
	if !ok {
		return nil, nil, fmt.Errorf("phase 3 did not produce *phasedSetup under %q", legacySetupKey)
	}

	// The executor Phase 3 component launched containers and registered with JD
	// (setting exec.Out and exec.Out.JDNodeID). Replace the TOML-loaded slice
	// in setup.In with those processed inputs so runPhasedEnvironmentFinish can
	// propose job specs to the correct JD node IDs.
	if execs, ok := priorOutputs["executor"].([]*executorsvc.Input); ok {
		setup.In.Executor = execs
	}

	cfg, phaseEffects, err := runPhasedEnvironmentFinish(ctx, setup)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, phaseEffects, nil
}
