package changesets

import (
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
)

// GenerateAggregatorConfigCfg is the configuration for the generate aggregator config changeset.
type GenerateAggregatorConfigCfg struct {
	// ServiceIdentifier is the identifier for this aggregator service (e.g. "default-aggregator")
	ServiceIdentifier string
	// CommitteeQualifier identifies which committee to generate config for
	CommitteeQualifier string
	// ChainSelectors are the chains the aggregator will support (both as source and destination)
	ChainSelectors []uint64
}

// GenerateAggregatorConfig creates a changeset that generates the aggregator configuration
// by scanning on-chain CommitteeVerifier contracts.
func GenerateAggregatorConfig() deployment.ChangeSetV2[GenerateAggregatorConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateAggregatorConfigCfg) error {
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
		}
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		envSelectors := e.BlockChains.ListChainSelectors()
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg GenerateAggregatorConfigCfg) (deployment.ChangesetOutput, error) {
		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}
		deps := sequences.GenerateAggregatorConfigDeps{
			Env: e,
		}

		input := sequences.GenerateAggregatorConfigInput{
			ServiceIdentifier:  cfg.ServiceIdentifier,
			CommitteeQualifier: cfg.CommitteeQualifier,
			ChainSelectors:     selectors,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateAggregatorConfig, deps, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate aggregator config: %w", err)
		}

		// Create a new datastore to return with the generated config
		outputDS := datastore.NewMemoryDataStore()

		// Save the generated config to the datastore's env metadata
		aggCfg := report.Output.Committee.ToModelCommittee()
		if err := deployments.SaveAggregatorConfig(outputDS, report.Output.ServiceIdentifier, aggCfg); err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to save aggregator config: %w", err)
		}

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
