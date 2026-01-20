package changesets

import (
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	verifierconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/verifier_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
)

type GenerateVerifierConfigCfg struct {
	CommitteeQualifier string
	ExecutorQualifier  string
	ChainSelectors     []uint64
	NOPAliases         []string
	NOPs               []verifierconfig.NOPInput
	Committee          verifierconfig.CommitteeInput
	PyroscopeURL       string
	Monitoring         shared.MonitoringInput
}

func GenerateVerifierConfig() deployment.ChangeSetV2[GenerateVerifierConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateVerifierConfigCfg) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}

		if len(cfg.Committee.Aggregators) == 0 {
			return fmt.Errorf("at least one aggregator is required")
		}

		nopSet := make(map[string]verifierconfig.NOPInput, len(cfg.NOPs))
		for _, nop := range cfg.NOPs {
			nopSet[nop.Alias] = nop
		}

		nopAliases := cfg.NOPAliases
		if len(nopAliases) == 0 {
			nopAliases = cfg.Committee.NOPAliases
		}

		for _, alias := range nopAliases {
			nop, ok := nopSet[alias]
			if !ok {
				return fmt.Errorf("NOP alias %q not found in NOPs input", alias)
			}
			if nop.SignerAddress == "" {
				return fmt.Errorf("NOP %q missing signer_address", alias)
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
		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}

		deps := sequences.GenerateVerifierConfigDeps{
			Env: e,
		}

		input := sequences.GenerateVerifierConfigInput{
			CommitteeQualifier: cfg.CommitteeQualifier,
			ExecutorQualifier:  cfg.ExecutorQualifier,
			ChainSelectors:     selectors,
			NOPAliases:         cfg.NOPAliases,
			NOPs:               cfg.NOPs,
			Committee:          cfg.Committee,
			PyroscopeURL:       cfg.PyroscopeURL,
			Monitoring:         cfg.Monitoring,
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
