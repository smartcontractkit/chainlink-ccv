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

// GenerateExecutorConfigCfg is the configuration for the generate executor config changeset.
type GenerateExecutorConfigCfg struct {
	TopologyPath      string
	ExecutorQualifier string
	ChainSelectors    []uint64
	NOPAliases        []string
}

// GenerateExecutorConfig creates a changeset that generates executor configurations
// for NOPs that are part of an executor pool. It iterates over specified NOPs (or all if empty)
// and generates a job spec for each NOP.
func GenerateExecutorConfig() deployment.ChangeSetV2[GenerateExecutorConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateExecutorConfigCfg) error {
		if cfg.TopologyPath == "" {
			return fmt.Errorf("topology path is required")
		}

		topology, err := deployments.LoadEnvironmentTopology(cfg.TopologyPath)
		if err != nil {
			return fmt.Errorf("failed to load environment topology: %w", err)
		}

		for _, alias := range cfg.NOPAliases {
			if !topology.NOPTopology.HasNOP(alias) {
				return fmt.Errorf("NOP alias %q not found in environment topology", alias)
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
		topology, err := deployments.LoadEnvironmentTopology(cfg.TopologyPath)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to load environment topology: %w", err)
		}

		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}

		deps := sequences.GenerateExecutorConfigDeps{
			Env:      e,
			Topology: topology,
		}

		input := sequences.GenerateExecutorConfigInput{
			ExecutorQualifier: cfg.ExecutorQualifier,
			ChainSelectors:    selectors,
			NOPAliases:        cfg.NOPAliases,
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
