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

// GenerateVerifierConfigCfg is the configuration for the generate verifier config changeset.
type GenerateVerifierConfigCfg struct {
	TopologyPath       string
	CommitteeQualifier string
	ExecutorQualifier  string
	ChainSelectors     []uint64
	NOPAliases         []string
}

// GenerateVerifierConfig creates a changeset that generates verifier configurations
// for NOPs that are part of committees. It iterates over specified NOPs (or all if empty)
// and generates a job spec for each (NOP, committee, aggregator) combination for HA support.
// The SignerAddress for each NOP is read from the NOPConfig in the EnvironmentTopology.
func GenerateVerifierConfig() deployment.ChangeSetV2[GenerateVerifierConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateVerifierConfigCfg) error {
		if cfg.TopologyPath == "" {
			return fmt.Errorf("topology path is required")
		}
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}

		topology, err := deployments.LoadEnvironmentTopology(cfg.TopologyPath)
		if err != nil {
			return fmt.Errorf("failed to load environment topology: %w", err)
		}

		if _, ok := topology.NOPTopology.Committees[cfg.CommitteeQualifier]; !ok {
			return fmt.Errorf("committee %q not found in environment topology", cfg.CommitteeQualifier)
		}

		nopAliases := cfg.NOPAliases
		if len(nopAliases) == 0 {
			nopAliases, err = topology.GetNOPsForCommittee(cfg.CommitteeQualifier)
			if err != nil {
				return fmt.Errorf("failed to get NOPs for committee: %w", err)
			}
		}

		for _, alias := range nopAliases {
			nop, ok := topology.NOPTopology.GetNOP(alias)
			if !ok {
				return fmt.Errorf("NOP alias %q not found in environment topology", alias)
			}
			if nop.SignerAddress == "" {
				return fmt.Errorf("NOP %q missing signer_address in env config", alias)
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

	apply := func(e deployment.Environment, cfg GenerateVerifierConfigCfg) (deployment.ChangesetOutput, error) {
		topology, err := deployments.LoadEnvironmentTopology(cfg.TopologyPath)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to load environment topology: %w", err)
		}

		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}

		deps := sequences.GenerateVerifierConfigDeps{
			Env:      e,
			Topology: topology,
		}

		input := sequences.GenerateVerifierConfigInput{
			CommitteeQualifier: cfg.CommitteeQualifier,
			ExecutorQualifier:  cfg.ExecutorQualifier,
			ChainSelectors:     selectors,
			NOPAliases:         cfg.NOPAliases,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateVerifierConfig, deps, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate verifier config: %w", err)
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
			}, fmt.Errorf("failed to save verifier job specs: %w", err)
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
			report.Output.VerifierSuffix,
			report.Output.ExpectedJobSpecIDs,
			scopedNOPs,
			report.Output.ExpectedNOPs,
		); err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to cleanup orphaned verifier job specs: %w", err)
		}

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
