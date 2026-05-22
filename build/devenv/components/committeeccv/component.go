package committeeccv

import (
	"context"
	"fmt"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
)

const configKey = "aggregator"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("committeeccv component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase4 performs all CommitteeCCV setup that depends on Phase 3 contract outputs:
//  1. Generates HMAC credentials for each aggregator (sets a partial agg.Out so verifiers
//     can obtain their credentials before the full aggregator container is started).
//  2. Assigns shared TLS certificates to each aggregator.
//  3. Launches standalone verifier containers.
//  4. Registers standalone verifiers with JD.
//  5. Enriches the shared topology pointer with signer keys from verifier bootstrap keys.
//  6. Generates aggregator committee configuration via changeset (sets agg.GeneratedCommittee).
//  7. Launches full aggregator containers (sets agg.Out on the shared pointer).
//
// Because priorOutputs is a shallow clone of the Phase 3 snapshot, all mutations to
// *AggregatorInput, *committeeverifier.Input, and *EnvironmentTopology are visible to
// later Phase 4 components (e.g. Indexer) and to Legacy Phase 4 via _cfg.
func (c *component) RunPhase4(
	ctx context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	aggregators, ok := priorOutputs["aggregators"].([]*services.AggregatorInput)
	if !ok || len(aggregators) == 0 {
		return map[string]any{}, nil, nil
	}

	verifiers, _ := priorOutputs["verifiers"].([]*committeeverifier.Input)
	sharedTLSCerts, _ := priorOutputs["shared_tls_certs"].(*services.TLSCertPaths)
	jdInfra, ok := priorOutputs["jd"].(*jobs.JDInfrastructure)
	if !ok || jdInfra == nil {
		return nil, nil, fmt.Errorf("committeeccv: jd not found in phase outputs")
	}
	e, ok := priorOutputs["_env"].(*deployment.Environment)
	if !ok || e == nil {
		return nil, nil, fmt.Errorf("committeeccv: _env not found in phase outputs")
	}
	topology, ok := priorOutputs["_topology"].(*ccvdeployment.EnvironmentTopology)
	if !ok || topology == nil {
		return nil, nil, fmt.Errorf("committeeccv: _topology not found in phase outputs")
	}
	blockchainOutputs, ok := priorOutputs["blockchainOutputs"].([]*blockchain.Output)
	if !ok {
		return nil, nil, fmt.Errorf("committeeccv: blockchainOutputs not found in phase outputs")
	}

	// Step 1 + 2: Generate HMAC creds and assign TLS certs for each aggregator.
	// Set a partial agg.Out so that verifiers can read credentials before the full
	// aggregator container exists.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		creds, err := agg.EnsureClientCredentials()
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: HMAC credentials for aggregator %q: %w", agg.CommitteeName, err)
		}
		if agg.Out == nil {
			agg.Out = &services.AggregatorOutput{}
		}
		agg.Out.ClientCredentials = creds
		agg.SharedTLSCerts = sharedTLSCerts
	}

	// Step 3: Launch standalone verifier containers.
	if len(verifiers) > 0 {
		modifiers := chainreg.GetRegistry().GetVerifierModifiers()
		if err := committeeverifier.LaunchStandaloneVerifiers(verifiers, aggregators, blockchainOutputs, jdInfra, modifiers); err != nil {
			return nil, nil, fmt.Errorf("committeeccv: launch verifiers: %w", err)
		}

		// Step 4: Register verifiers with JD.
		if err := committeeverifier.RegisterStandaloneVerifiersWithJD(ctx, verifiers, jdInfra.OffchainClient); err != nil {
			return nil, nil, fmt.Errorf("committeeccv: register verifiers with JD: %w", err)
		}

		// Step 5: Enrich shared topology pointer with signer keys.
		ccdeploy.EnrichTopologyWithVerifiers(topology, verifiers)
	}

	// Step 6: Generate aggregator committee configuration.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		instanceName := agg.InstanceName()
		committee, ok := topology.NOPTopology.Committees[agg.CommitteeName]
		if !ok {
			return nil, nil, fmt.Errorf("committeeccv: committee %q not found in topology", agg.CommitteeName)
		}
		cs := ccvchangesets.GenerateAggregatorConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.GenerateAggregatorConfigInput{
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: agg.CommitteeName,
			ChainSelectors:     ccvchangesets.CommitteeChainSelectorsFromTopology(committee),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: GenerateAggregatorConfig for %q: %w", instanceName, err)
		}
		aggCfg, err := ccvdeployment.GetAggregatorConfig(output.DataStore.Seal(), instanceName+"-aggregator")
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: get aggregator config for %q: %w", instanceName, err)
		}
		agg.GeneratedCommittee = aggCfg
		e.DataStore = output.DataStore.Seal()
	}

	// Step 7: Launch full aggregator containers.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		out, err := services.NewAggregator(agg)
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: starting aggregator %q: %w", agg.CommitteeName, err)
		}
		agg.Out = out
	}

	return map[string]any{}, nil, nil
}
