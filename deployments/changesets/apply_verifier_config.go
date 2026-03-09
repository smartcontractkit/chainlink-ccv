package changesets

import (
	"fmt"
	"slices"
	"strconv"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/fetch_node_chain_support"
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
	// TargetNOPs limits which NOPs to update. Defaults to all in committee.
	TargetNOPs []shared.NOPAlias
	// DisableFinalityCheckers is a list of chain selectors (as strings) for which
	// the finality violation checker should be disabled.
	DisableFinalityCheckers []string
	// RevokeOrphanedJobs when true revokes and cleans up orphaned jobs; default false.
	RevokeOrphanedJobs bool
}

type VerifierApplyDeps struct {
	Env      deployment.Environment
	JDClient shared.JDClient
	NodeIDs  []string
}

func makeVerifierApply(
	applyFn func(VerifierApplyDeps, ApplyVerifierConfigCfg) (deployment.ChangesetOutput, error),
) func(deployment.Environment, ApplyVerifierConfigCfg) (deployment.ChangesetOutput, error) {
	return func(e deployment.Environment, cfg ApplyVerifierConfigCfg) (deployment.ChangesetOutput, error) {
		return applyFn(VerifierApplyDeps{
			Env:      e,
			JDClient: e.Offchain,
			NodeIDs:  e.NodeIDs,
		}, cfg)
	}
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

		if shared.IsProductionEnvironment(e.Name) {
			if cfg.Topology.PyroscopeURL != "" {
				return fmt.Errorf("pyroscope URL is not supported for production environments")
			}
		}

		return nil
	}

	return deployment.CreateChangeSet(makeVerifierApply(ApplyVerifierConfigWithDeps), validate)
}

func ApplyVerifierConfigWithDeps(deps VerifierApplyDeps, cfg ApplyVerifierConfigCfg) (deployment.ChangesetOutput, error) {
	committee := cfg.Topology.NOPTopology.Committees[cfg.CommitteeQualifier]
	selectors, err := getCommitteeChainSelectors(committee)
	if err != nil {
		return deployment.ChangesetOutput{}, err
	}
	signingKeysByNOP := fetchSigningKeysForNOPs(deps, cfg.Topology.NOPTopology.NOPs)

	nopsToValidate := cfg.TargetNOPs
	if len(nopsToValidate) == 0 {
		nopsToValidate = shared.ConvertStringToNopAliases(getCommitteeNOPAliases(committee))
	}

	if err := validateVerifierChainSupport(deps, nopsToValidate, committee); err != nil {
		return deployment.ChangesetOutput{}, err
	}

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
		DisableFinalityCheckers:  cfg.DisableFinalityCheckers,
	}

	report, err := operations.ExecuteSequence(deps.Env.OperationsBundle, sequences.GenerateVerifierConfig, sequences.GenerateVerifierConfigDeps{Env: deps.Env}, input)
	if err != nil {
		return deployment.ChangesetOutput{
			Reports: report.ExecutionReports,
		}, fmt.Errorf("failed to generate verifier config: %w", err)
	}

	manageReport, err := operations.ExecuteSequence(
		deps.Env.OperationsBundle,
		sequences.ManageJobProposals,
		sequences.ManageJobProposalsDeps{Env: deps.Env},
		sequences.ManageJobProposalsInput{
			JobSpecs:           report.Output.JobSpecs,
			AffectedScope:      report.Output.AffectedScope,
			Labels:             map[string]string{"job_type": "verifier", "committee": cfg.CommitteeQualifier},
			NOPs:               sequences.NOPContext{Modes: buildNOPModes(cfg.Topology.NOPTopology.NOPs), TargetNOPs: cfg.TargetNOPs, AllNOPs: getAllNOPAliases(cfg.Topology.NOPTopology.NOPs)},
			RevokeOrphanedJobs: cfg.RevokeOrphanedJobs,
		},
	)
	if err != nil {
		return deployment.ChangesetOutput{
			Reports: report.ExecutionReports,
		}, fmt.Errorf("failed to manage job proposals: %w", err)
	}

	deps.Env.Logger.Infow("Verifier config applied",
		"jobsCount", len(manageReport.Output.Jobs),
		"revokedCount", len(manageReport.Output.RevokedJobs))

	return deployment.ChangesetOutput{
		Reports:   report.ExecutionReports,
		DataStore: manageReport.Output.DataStore,
	}, nil
}

func fetchSigningKeysForNOPs(deps VerifierApplyDeps, nops []deployments.NOPConfig) fetch_signing_keys.SigningKeysByNOP {
	if deps.JDClient == nil {
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

	report, err := operations.ExecuteOperation(
		deps.Env.OperationsBundle,
		fetch_signing_keys.FetchNOPSigningKeys,
		fetch_signing_keys.FetchSigningKeysDeps{
			JDClient: deps.JDClient,
			Logger:   deps.Env.Logger,
			NodeIDs:  deps.NodeIDs,
		},
		fetch_signing_keys.FetchSigningKeysInput{
			NOPAliases: aliases,
		},
	)
	if err != nil {
		deps.Env.Logger.Warnw("Failed to fetch signing keys from JD", "error", err)
		return nil
	}

	return report.Output.SigningKeysByNOP
}

func convertNOPsToVerifierInput(
	nops []deployments.NOPConfig,
	signingKeysByNOP fetch_signing_keys.SigningKeysByNOP,
) []verifierconfig.NOPInput {
	result := make([]verifierconfig.NOPInput, len(nops))

	for i, nop := range nops {
		signerAddressesFromTopology := nop.SignerAddressByFamily

		if signer, ok := signerFromJDIfMissing(
			signerAddressesFromTopology,
			nop.Alias,
			chainsel.FamilyEVM,
			signingKeysByNOP,
		); ok {
			if signerAddressesFromTopology == nil {
				signerAddressesFromTopology = make(map[string]string)
			}
			signerAddressesFromTopology[chainsel.FamilyEVM] = signer
		}

		result[i] = verifierconfig.NOPInput{
			Alias:                 shared.NOPAlias(nop.Alias),
			SignerAddressByFamily: signerAddressesFromTopology,
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

func validateVerifierChainSupport(
	deps VerifierApplyDeps,
	nopsToValidate []shared.NOPAlias,
	committee deployments.CommitteeConfig,
) error {
	if deps.JDClient == nil {
		deps.Env.Logger.Debugw("Offchain client not available, skipping chain support validation")
		return nil
	}

	nopAliasStrings := shared.ConvertNopAliasToString(nopsToValidate)
	supportedChains, err := fetchNodeChainSupportForNOPs(deps, nopAliasStrings)
	if err != nil {
		return fmt.Errorf("failed to fetch node chain support: %w", err)
	}
	if supportedChains == nil {
		return nil
	}

	var validationResults []shared.ChainValidationResult
	for _, nopAlias := range nopsToValidate {
		requiredChains, err := getRequiredChainsForNOP(string(nopAlias), committee)
		if err != nil {
			return err
		}
		result := shared.ValidateNOPChainSupport(
			string(nopAlias),
			requiredChains,
			supportedChains[string(nopAlias)],
		)
		if result != nil {
			validationResults = append(validationResults, *result)
		}
	}

	return shared.FormatChainValidationError(validationResults)
}

func fetchNodeChainSupportForNOPs(deps VerifierApplyDeps, nopAliases []string) (shared.ChainSupportByNOP, error) {
	if len(nopAliases) == 0 {
		return nil, nil
	}

	report, err := operations.ExecuteOperation(
		deps.Env.OperationsBundle,
		fetch_node_chain_support.FetchNodeChainSupport,
		fetch_node_chain_support.FetchNodeChainSupportDeps{
			JDClient: deps.JDClient,
			Logger:   deps.Env.Logger,
			NodeIDs:  deps.NodeIDs,
		},
		fetch_node_chain_support.FetchNodeChainSupportInput{
			NOPAliases: nopAliases,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch node chain support from JD: %w", err)
	}

	return report.Output.SupportedChains, nil
}

func getRequiredChainsForNOP(nopAlias string, committee deployments.CommitteeConfig) ([]uint64, error) {
	var requiredChains []uint64
	for chainSelectorStr, chainConfig := range committee.ChainConfigs {
		if slices.Contains(chainConfig.NOPAliases, nopAlias) {
			sel, err := strconv.ParseUint(chainSelectorStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("committee chain_configs key %q is not a valid chain selector: %w", chainSelectorStr, err)
			}
			requiredChains = append(requiredChains, sel)
		}
	}
	return requiredChains, nil
}
