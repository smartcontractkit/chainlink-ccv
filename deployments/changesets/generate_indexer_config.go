package changesets

import (
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	idxconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/indexer_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
)

// GenerateIndexerConfigCfg is an alias for the changeset input type.
type GenerateIndexerConfigCfg = idxconfig.BuildConfigInput

// GenerateIndexerConfig creates a changeset that generates the indexer configuration
// by scanning on-chain CommitteeVerifier contracts.
func GenerateIndexerConfig() deployment.ChangeSetV2[idxconfig.BuildConfigInput] {
	validate := func(e deployment.Environment, cfg idxconfig.BuildConfigInput) error {
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
		}
		if len(cfg.CommitteeQualifiers) == 0 {
			return fmt.Errorf("at least one committee qualifier is required")
		}
		envSelectors := e.BlockChains.ListChainSelectors()
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg idxconfig.BuildConfigInput) (deployment.ChangesetOutput, error) {
		input := cfg
		if len(input.ChainSelectors) == 0 {
			input.ChainSelectors = e.BlockChains.ListChainSelectors()
		}
		deps := sequences.GenerateIndexerConfigDeps{
			Env: e,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateIndexerConfig, deps, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate indexer config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{
					Reports: report.ExecutionReports,
				}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		idxCfg := idxconfig.GeneratedVerifiersToGeneratedConfig(report.Output.Verifiers)
		if err := deployments.SaveIndexerConfig(outputDS, report.Output.ServiceIdentifier, idxCfg); err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to save indexer config: %w", err)
		}

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
