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

// GenerateIndexerConfigCfg is the configuration for the generate indexer config changeset.
type GenerateIndexerConfigCfg struct {
	// ServiceIdentifier is the identifier for this indexer service (e.g. "default-indexer")
	ServiceIdentifier string
	// CommitteeQualifiers are the committees to generate config for, in order matching [[Verifier]] entries
	CommitteeQualifiers []string
	// ChainSelectors are the source chains the indexer will monitor
	ChainSelectors []uint64
}

// GenerateIndexerConfig creates a changeset that generates the indexer configuration
// by scanning on-chain CommitteeVerifier contracts.
func GenerateIndexerConfig() deployment.ChangeSetV2[GenerateIndexerConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateIndexerConfigCfg) error {
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

	apply := func(e deployment.Environment, cfg GenerateIndexerConfigCfg) (deployment.ChangesetOutput, error) {
		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}
		deps := sequences.GenerateIndexerConfigDeps{
			Env: e,
		}

		input := sequences.GenerateIndexerConfigInput{
			ServiceIdentifier:    cfg.ServiceIdentifier,
			CommitteeQualifiers:  cfg.CommitteeQualifiers,
			SourceChainSelectors: selectors,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateIndexerConfig, deps, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate indexer config: %w", err)
		}

		// Create a new datastore to return with the generated config
		outputDS := datastore.NewMemoryDataStore()

		// Save the generated config to the datastore's env metadata
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
