package committeeccv

import (
	"context"
	"fmt"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
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

// RunPhase4 performs CommitteeCCV setup that depends on Phase 3 contract outputs:
//  1. Assigns shared TLS certificates to each aggregator.
//  2. Enriches the shared topology pointer with signer keys from verifier bootstrap keys
//     (verifiers were already launched and registered with JD in Legacy Phase 2).
//  3. Generates aggregator committee configuration via changeset (sets agg.GeneratedCommittee).
//  4. Launches full aggregator containers (sets agg.Out on the shared pointer).
//
// Because priorOutputs is a shallow clone of the Phase 3 snapshot, all mutations to
// *AggregatorInput and *EnvironmentTopology are visible to later Phase 4 components
// (e.g. Indexer) and to Legacy Phase 4 via _cfg.
func (c *component) RunPhase4(
	_ context.Context,
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
	e, ok := priorOutputs["_env"].(*deployment.Environment)
	if !ok || e == nil {
		return nil, nil, fmt.Errorf("committeeccv: _env not found in phase outputs")
	}
	topology, ok := priorOutputs["_topology"].(*ccvdeployment.EnvironmentTopology)
	if !ok || topology == nil {
		return nil, nil, fmt.Errorf("committeeccv: _topology not found in phase outputs")
	}

	// Step 1: Assign shared TLS certificates to each aggregator.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		agg.SharedTLSCerts = sharedTLSCerts
	}

	// Step 2: Enrich topology with verifier signer keys.
	// Verifiers were launched and registered with JD in Legacy Phase 2, so their
	// Out.BootstrapKeys are already populated.
	if len(verifiers) > 0 {
		ccdeploy.EnrichTopologyWithVerifiers(topology, verifiers)
	}

	// Step 3: Generate aggregator committee configuration.
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

	// Step 4: Launch full aggregator containers.
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
