package changesets

import (
	"fmt"
	"slices"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/fetch_signing_keys"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	verifierconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/verifier_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
)

type ApplyVerifierConfigCfg struct {
	Topology *deployments.EnvironmentTopology
	// CommitteeQualifier identifies which committee from topology to use
	CommitteeQualifier string
	// DefaultExecutorQualifier is the qualifier of the default executor
	DefaultExecutorQualifier string
	// ChainSelectors limits which chains to configure. Defaults to all.
	ChainSelectors []uint64
	// TargetNOPs limits which NOPs to update. Defaults to all in committee.
	TargetNOPs []shared.NOPAlias
}

func ApplyVerifierConfig() deployment.ChangeSetV2[ApplyVerifierConfigCfg] {
	validate := func(e deployment.Environment, cfg ApplyVerifierConfigCfg) error {
		if cfg.Topology == nil {
			return fmt.Errorf("topology is required")
		}

		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}

		if cfg.DefaultExecutorQualifier == "" {
			return fmt.Errorf("default executor qualifier is required")
		}

		committee, ok := cfg.Topology.NOPTopology.Committees[cfg.CommitteeQualifier]
		if !ok {
			return fmt.Errorf("committee %q not found in topology", cfg.CommitteeQualifier)
		}

		if len(committee.Aggregators) == 0 {
			return fmt.Errorf("at least one aggregator is required for committee %q", cfg.CommitteeQualifier)
		}

		nopSet := make(map[string]bool)
		for _, nop := range cfg.Topology.NOPTopology.NOPs {
			nopSet[nop.Alias] = true
		}

		nopAliases := cfg.TargetNOPs
		if len(nopAliases) == 0 {
			nopAliases = shared.ConvertStringToNopAliases(getCommitteeNOPAliases(committee))
		}

		for _, alias := range nopAliases {
			if !nopSet[string(alias)] {
				return fmt.Errorf("NOP alias %q not found in topology", alias)
			}
		}

		envSelectors := e.BlockChains.ListChainSelectors()
		committeeChains := getCommitteeChainSelectors(committee)
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
			if !slices.Contains(committeeChains, s) {
				return fmt.Errorf("chain %d not configured in committee %q", s, cfg.CommitteeQualifier)
			}
		}

		if shared.IsProductionEnvironment(e.Name) {
			if cfg.Topology.PyroscopeURL != "" {
				return fmt.Errorf("pyroscope URL is not supported for production environments")
			}
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg ApplyVerifierConfigCfg) (deployment.ChangesetOutput, error) {
		committee := cfg.Topology.NOPTopology.Committees[cfg.CommitteeQualifier]
		committeeChains := getCommitteeChainSelectors(committee)

		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = committeeChains
		} else {
			selectors = filterChains(selectors, committeeChains)
		}
		signingKeysByNOP := fetchSigningKeysForNOPs(e, cfg.Topology.NOPTopology.NOPs)
		environmentNOPs := convertNOPsToVerifierInput(cfg.Topology.NOPTopology.NOPs, signingKeysByNOP)
		committeeInput := convertTopologyCommittee(committee)
		monitoring := convertTopologyMonitoring(&cfg.Topology.Monitoring)

		input := sequences.GenerateVerifierConfigInput{
			DefaultExecutorQualifier: cfg.DefaultExecutorQualifier,
			ChainSelectors:           selectors,
			TargetNOPs:               cfg.TargetNOPs,
			EnvironmentNOPs:          environmentNOPs,
			Committee:                committeeInput,
			PyroscopeURL:             cfg.Topology.PyroscopeURL,
			Monitoring:               monitoring,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateVerifierConfig, sequences.GenerateVerifierConfigDeps{Env: e}, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate verifier config: %w", err)
		}

		manageReport, err := operations.ExecuteSequence(
			e.OperationsBundle,
			sequences.ManageJobProposals,
			sequences.ManageJobProposalsDeps{Env: e},
			sequences.ManageJobProposalsInput{
				JobSpecs:      report.Output.JobSpecs,
				AffectedScope: report.Output.AffectedScope,
				Labels: map[string]string{
					"job_type":  "verifier",
					"committee": cfg.CommitteeQualifier,
				},
				NOPs: sequences.NOPContext{
					Modes:      buildNOPModes(cfg.Topology.NOPTopology.NOPs),
					TargetNOPs: cfg.TargetNOPs,
					AllNOPs:    getAllNOPAliases(cfg.Topology.NOPTopology.NOPs),
				},
			},
		)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to manage job proposals: %w", err)
		}

		e.Logger.Infow("Verifier config applied",
			"jobsCount", len(manageReport.Output.Jobs),
			"revokedCount", len(manageReport.Output.RevokedJobs))

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: manageReport.Output.DataStore,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func fetchSigningKeysForNOPs(e deployment.Environment, nops []deployments.NOPConfig) fetch_signing_keys.SigningKeysByNOP {
	if e.Offchain == nil {
		return nil
	}

	aliases := make([]string, 0, len(nops))
	for _, nop := range nops {
		if nop.SignerAddressByFamily == nil || nop.SignerAddressByFamily[chainsel.FamilyEVM] == "" {
			aliases = append(aliases, nop.Alias)
		}
	}

	if len(aliases) == 0 {
		return nil
	}

	if e.Offchain == nil {
		e.Logger.Debugw("Offchain client not available, skipping signing key fetch")
		return nil
	}

	report, err := operations.ExecuteOperation(
		e.OperationsBundle,
		fetch_signing_keys.FetchNOPSigningKeys,
		fetch_signing_keys.FetchSigningKeysDeps{
			JDClient: e.Offchain,
			Logger:   e.Logger,
			NodeIDs:  e.NodeIDs,
		},
		fetch_signing_keys.FetchSigningKeysInput{
			NOPAliases: aliases,
		},
	)
	if err != nil {
		e.Logger.Warnw("Failed to fetch signing keys from JD", "error", err)
		return nil
	}

	return report.Output.SigningKeysByNOP
}

func convertNOPsToVerifierInput(nops []deployments.NOPConfig, signingKeysByNOP fetch_signing_keys.SigningKeysByNOP) []verifierconfig.NOPInput {
	result := make([]verifierconfig.NOPInput, len(nops))
	for i, nop := range nops {
		signerAddresses := nop.SignerAddressByFamily

		if (signerAddresses == nil || signerAddresses[chainsel.FamilyEVM] == "") && signingKeysByNOP != nil {
			if jdSigners, ok := signingKeysByNOP[nop.Alias]; ok {
				if evmSigner, ok := jdSigners[chainsel.FamilyEVM]; ok && evmSigner != "" {
					if signerAddresses == nil {
						signerAddresses = make(map[string]string)
					}
					signerAddresses[chainsel.FamilyEVM] = evmSigner
				}
			}
		}

		result[i] = verifierconfig.NOPInput{
			Alias:                 shared.NOPAlias(nop.Alias),
			SignerAddressByFamily: signerAddresses,
			Mode:                  nop.GetMode(),
		}
	}
	return result
}

func convertTopologyCommittee(committee deployments.CommitteeConfig) verifierconfig.CommitteeInput {
	aggregators := make([]verifierconfig.AggregatorInput, len(committee.Aggregators))
	for i, agg := range committee.Aggregators {
		aggregators[i] = verifierconfig.AggregatorInput{
			Name:                         agg.Name,
			Address:                      agg.Address,
			InsecureAggregatorConnection: agg.InsecureAggregatorConnection,
		}
	}

	chainNOPAliases := make(map[string][]shared.NOPAlias, len(committee.ChainConfigs))
	for chainSelector, chainConfig := range committee.ChainConfigs {
		chainNOPAliases[chainSelector] = shared.ConvertStringToNopAliases(chainConfig.NOPAliases)
	}

	return verifierconfig.CommitteeInput{
		Qualifier:       committee.Qualifier,
		Aggregators:     aggregators,
		NOPAliases:      shared.ConvertStringToNopAliases(getCommitteeNOPAliases(committee)),
		ChainNOPAliases: chainNOPAliases,
	}
}

func getCommitteeNOPAliases(committee deployments.CommitteeConfig) []string {
	aliasSet := make(map[string]bool)
	for _, chainConfig := range committee.ChainConfigs {
		for _, alias := range chainConfig.NOPAliases {
			aliasSet[alias] = true
		}
	}
	aliases := make([]string, 0, len(aliasSet))
	for alias := range aliasSet {
		aliases = append(aliases, alias)
	}
	return aliases
}
