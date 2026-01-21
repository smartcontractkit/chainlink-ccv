package changesets

import (
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	executorconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/executor_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
)

type GenerateExecutorConfigCfg struct {
	// ExecutorQualifier is the qualifier of the executor that is configured as part of the changeset.
	ExecutorQualifier string
	// ChainSelectors is the list of chain selectors that will be considered. Defaults to all chain selectors in the environment.
	ChainSelectors []uint64
	// NOPAliases is the scope of nop that are affected by the changeset. Defaults to all nop aliases in the executor pool.
	NOPAliases []string
	// ExecutorPool is the executor pool configuration.
	ExecutorPool executorconfig.ExecutorPoolInput
	// IndexerAddress is the address of the indexer to use for the executor.
	IndexerAddress string
	// PyroscopeURL is the URL of the Pyroscope server.
	PyroscopeURL string
	// Monitoring is the monitoring configuration. It contains the beholder configuration.
	Monitoring shared.MonitoringInput
}

func GenerateExecutorConfig() deployment.ChangeSetV2[GenerateExecutorConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateExecutorConfigCfg) error {
		if cfg.IndexerAddress == "" {
			return fmt.Errorf("indexer address is required")
		}

		if len(cfg.ExecutorPool.NOPAliases) == 0 {
			return fmt.Errorf("executor pool NOPs are required")
		}

		for _, alias := range cfg.NOPAliases {
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

		deps := sequences.GenerateExecutorConfigDeps{
			Env: e,
		}

		input := sequences.GenerateExecutorConfigInput{
			ExecutorQualifier: cfg.ExecutorQualifier,
			ChainSelectors:    selectors,
			NOPAliases:        cfg.NOPAliases,
			ExecutorPool:      cfg.ExecutorPool,
			IndexerAddress:    cfg.IndexerAddress,
			PyroscopeURL:      cfg.PyroscopeURL,
			Monitoring:        cfg.Monitoring,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateExecutorConfig, deps, input)
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
		if len(cfg.NOPAliases) > 0 {
			scopedNOPs = make(map[string]bool)
			for _, nopAlias := range cfg.NOPAliases {
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
