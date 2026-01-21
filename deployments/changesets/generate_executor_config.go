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

type GenerateExecutorConfigCfg = sequences.GenerateExecutorConfigInput

func GenerateExecutorConfig() deployment.ChangeSetV2[GenerateExecutorConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateExecutorConfigCfg) error {
		if cfg.IndexerAddress == "" {
			return fmt.Errorf("indexer address is required")
		}

		if len(cfg.ExecutorPool.NOPAliases) == 0 {
			return fmt.Errorf("executor pool NOPs are required")
		}

		for _, alias := range cfg.TargetNOPs {
			if !slices.Contains(cfg.ExecutorPool.NOPAliases, alias) {
				return fmt.Errorf("NOP alias %q not found in executor pool", alias)
			}
		}
		envSelectors := e.BlockChains.ListChainSelectors()
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg GenerateExecutorConfigCfg) (deployment.ChangesetOutput, error) {
		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}

		input := cfg
		input.ChainSelectors = selectors

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateExecutorConfig, sequences.GenerateExecutorConfigDeps{Env: e}, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate executor config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{
					Reports: report.ExecutionReports,
				}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		if err := deployments.SaveNOPJobSpecs(outputDS, report.Output.JobSpecs); err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to save executor job specs: %w", err)
		}

		var scopedNOPs map[string]bool
		if len(cfg.TargetNOPs) > 0 {
			scopedNOPs = make(map[string]bool)
			for _, nopAlias := range cfg.TargetNOPs {
				scopedNOPs[nopAlias] = true
			}
		}

		if err := deployments.CleanupOrphanedJobSpecs(
			outputDS,
			report.Output.ExecutorSuffix,
			report.Output.ExpectedJobSpecIDs,
			scopedNOPs,
			nil,
		); err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to cleanup orphaned executor job specs: %w", err)
		}

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
