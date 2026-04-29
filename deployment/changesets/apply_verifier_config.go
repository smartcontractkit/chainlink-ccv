package changesets

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/BurntSushi/toml"
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_signing_keys"
	"github.com/smartcontractkit/chainlink-ccv/deployment/sequences"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type ApplyVerifierConfigInput struct {
	Topology                 *ccvdeployment.EnvironmentTopology
	CommitteeQualifier       string
	DefaultExecutorQualifier string
	TargetNOPs               []shared.NOPAlias
	DisableFinalityCheckers  []string
	// RevokeOrphanedJobs when true revokes and cleans up orphaned jobs; default false.
	RevokeOrphanedJobs bool
}

func ApplyVerifierConfig(registry *adapters.Registry) deployment.ChangeSetV2[ApplyVerifierConfigInput] {
	validate := func(e deployment.Environment, cfg ApplyVerifierConfigInput) error {
		if cfg.Topology == nil {
			return fmt.Errorf("topology is required")
		}

		if cfg.Topology.NOPTopology == nil || len(cfg.Topology.NOPTopology.NOPs) == 0 {
			return fmt.Errorf("NOP topology with at least one NOP is required")
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

	apply := func(e deployment.Environment, cfg ApplyVerifierConfigInput) (deployment.ChangesetOutput, error) {
		committee := cfg.Topology.NOPTopology.Committees[cfg.CommitteeQualifier]
		selectors, err := getCommitteeChainSelectors(committee)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		if len(selectors) == 0 {
			return runOrphanJobCleanup(
				e,
				cfg.RevokeOrphanedJobs,
				shared.VerifierJobScope{CommitteeQualifier: cfg.CommitteeQualifier},
				map[string]string{"job_type": "verifier", "committee": cfg.CommitteeQualifier},
				buildNOPModes(cfg.Topology.NOPTopology.NOPs),
				cfg.TargetNOPs,
				getAllNOPAliases(cfg.Topology.NOPTopology.NOPs),
				"No chain configs found for committee, nothing to do",
				"No chain configs for committee, running orphan cleanup only",
				"committee", cfg.CommitteeQualifier,
			)
		}

		// Derive the signing key family from the registered adapter — no hardcoded chain family.
		signerFamily, err := getSignerFamilyFromRegistry(registry, selectors)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to determine signer address family: %w", err)
		}

		nopsToValidate := cfg.TargetNOPs
		if len(nopsToValidate) == 0 {
			nopsToValidate = shared.ConvertStringToNopAliases(getCommitteeNOPAliases(committee))
		}

		targetedNOPs := filterNOPsByAliases(cfg.Topology.NOPTopology.NOPs, shared.ConvertNopAliasToString(nopsToValidate))
		signingKeysByNOP, err := fetchSigningKeysForNOPs(e, targetedNOPs, signerFamily)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to fetch signing keys: %w", err)
		}

		clNOPs := filterCLModeNOPs(nopsToValidate, cfg.Topology.NOPTopology.NOPs)
		if err := validateVerifierChainSupport(e, clNOPs, committee); err != nil {
			return deployment.ChangesetOutput{}, err
		}

		contractAddresses, err := buildVerifierContractConfigs(registry, e, selectors, cfg.CommitteeQualifier, cfg.DefaultExecutorQualifier)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		nopInputs := convertNOPsToVerifierInput(cfg.Topology.NOPTopology.NOPs, signingKeysByNOP, signerFamily)
		committeeInput := convertTopologyCommittee(committee)

		jobSpecs, scope, err := buildVerifierJobSpecs(
			contractAddresses,
			cfg.TargetNOPs,
			nopInputs,
			committeeInput,
			cfg.Topology.PyroscopeURL,
			cfg.Topology.Monitoring,
			cfg.DisableFinalityCheckers,
			signerFamily,
		)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		nopModes := buildNOPModes(cfg.Topology.NOPTopology.NOPs)

		manageReport, err := operations.ExecuteSequence(
			e.OperationsBundle,
			sequences.ManageJobProposals,
			sequences.ManageJobProposalsDeps{Env: e},
			sequences.ManageJobProposalsInput{
				JobSpecs:      jobSpecs,
				AffectedScope: scope,
				Labels: map[string]string{
					"job_type":  "verifier",
					"committee": cfg.CommitteeQualifier,
				},
				NOPs: sequences.NOPContext{
					Modes:      nopModes,
					TargetNOPs: cfg.TargetNOPs,
					AllNOPs:    getAllNOPAliases(cfg.Topology.NOPTopology.NOPs),
				},
				RevokeOrphanedJobs: cfg.RevokeOrphanedJobs,
			},
		)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: manageReport.ExecutionReports,
			}, fmt.Errorf("failed to manage job proposals: %w", err)
		}

		e.Logger.Infow("Verifier config applied",
			"jobsCount", len(manageReport.Output.Jobs),
			"revokedCount", len(manageReport.Output.RevokedJobs))

		return deployment.ChangesetOutput{
			Reports:   manageReport.ExecutionReports,
			DataStore: manageReport.Output.DataStore,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// getSignerFamilyFromRegistry returns the signing key family implied by the selected
// chains. If a verifier adapter is registered for a selector, it must agree with the
// family derived from that selector.
func getSignerFamilyFromRegistry(registry *adapters.Registry, selectors []uint64) (string, error) {
	if len(selectors) == 0 {
		return "", fmt.Errorf("at least one committee chain selector is required")
	}

	var signerFamily string
	for _, sel := range selectors {
		family, err := chainsel.GetSelectorFamily(sel)
		if err != nil {
			return "", fmt.Errorf("failed to get chain family for selector %d: %w", sel, err)
		}
		if signerFamily == "" {
			signerFamily = family
		} else if family != signerFamily {
			return "", fmt.Errorf(
				"committee chain selectors span multiple signer families: %q and %q",
				signerFamily, family,
			)
		}

		a, err := registry.GetByChain(sel)
		if err != nil || a.Verifier == nil {
			continue
		}
		if adapterFamily := a.Verifier.GetSignerAddressFamily(); adapterFamily != signerFamily {
			return "", fmt.Errorf(
				"chain %d: verifier adapter signer family %q does not match chain family %q",
				sel, adapterFamily, signerFamily,
			)
		}
	}
	return signerFamily, nil
}

func buildVerifierContractConfigs(
	registry *adapters.Registry,
	e deployment.Environment,
	selectors []uint64,
	committeeQualifier string,
	executorQualifier string,
) (map[string]*adapters.VerifierContractAddresses, error) {
	configs := make(map[string]*adapters.VerifierContractAddresses, len(selectors))
	for _, sel := range selectors {
		a, err := registry.GetByChain(sel)
		if err != nil {
			return nil, fmt.Errorf("no adapter for chain %d: %w", sel, err)
		}
		if a.Verifier == nil {
			return nil, fmt.Errorf("no verifier config adapter registered for chain %d", sel)
		}
		addrs, err := a.Verifier.ResolveVerifierContractAddresses(e.DataStore, sel, committeeQualifier, executorQualifier)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve contract addresses for chain %d: %w", sel, err)
		}
		configs[strconv.FormatUint(sel, 10)] = addrs
	}
	return configs, nil
}

type verifierNOPInput struct {
	Alias                 shared.NOPAlias
	SignerAddressByFamily map[string]string
	Mode                  shared.NOPMode
}

type verifierAggregatorInput struct {
	Name                         string
	Address                      string
	InsecureAggregatorConnection bool
}

type verifierCommitteeInput struct {
	Qualifier       string
	Aggregators     []verifierAggregatorInput
	NOPAliases      []shared.NOPAlias
	ChainNOPAliases map[string][]shared.NOPAlias
}

func buildVerifierJobSpecs(
	contractAddresses map[string]*adapters.VerifierContractAddresses,
	targetNOPs []shared.NOPAlias,
	environmentNOPs []verifierNOPInput,
	committee verifierCommitteeInput,
	pyroscopeURL string,
	monitoring ccvdeployment.MonitoringConfig,
	disableFinalityCheckers []string,
	signerFamily string,
) (shared.NOPJobSpecs, shared.VerifierJobScope, error) {
	scope := shared.VerifierJobScope{
		CommitteeQualifier: committee.Qualifier,
	}

	nopByAlias := make(map[shared.NOPAlias]verifierNOPInput, len(environmentNOPs))
	for _, nop := range environmentNOPs {
		nopByAlias[nop.Alias] = nop
	}

	nopAliases := targetNOPs
	if len(nopAliases) == 0 {
		nopAliases = committee.NOPAliases
	}

	committeeVerifierAddrs := make(map[string]string, len(contractAddresses))
	onRampAddrs := make(map[string]string, len(contractAddresses))
	executorOnRampAddrs := make(map[string]string, len(contractAddresses))
	rmnRemoteAddrs := make(map[string]string, len(contractAddresses))

	for chainSel, addrs := range contractAddresses {
		committeeVerifierAddrs[chainSel] = addrs.CommitteeVerifierAddress
		onRampAddrs[chainSel] = addrs.OnRampAddress
		executorOnRampAddrs[chainSel] = addrs.ExecutorProxyAddress
		rmnRemoteAddrs[chainSel] = addrs.RMNRemoteAddress
	}

	jobSpecs := make(shared.NOPJobSpecs)

	for _, nopAlias := range nopAliases {
		nop, ok := nopByAlias[nopAlias]
		if !ok {
			return nil, scope, fmt.Errorf("NOP %q not found in input", nopAlias)
		}

		nopChains := getNOPChainMembership(nopAlias, committee.ChainNOPAliases)

		if len(committee.ChainNOPAliases) > 0 && len(nopChains) == 0 {
			continue
		}

		for _, agg := range committee.Aggregators {
			verifierJobID := shared.NewVerifierJobID(nopAlias, agg.Name, scope)

			signerAddress := nop.SignerAddressByFamily[signerFamily]
			if signerAddress == "" {
				return nil, scope, fmt.Errorf("NOP %q missing signer address for family %s", nop.Alias, signerFamily)
			}

			sortedFinalityCheckers := slices.Clone(disableFinalityCheckers)
			slices.Sort(sortedFinalityCheckers)

			verifierCfg := commit.Config{
				VerifierID:                     verifierJobID.GetVerifierID(),
				AggregatorAddress:              agg.Address,
				InsecureAggregatorConnection:   agg.InsecureAggregatorConnection,
				SignerAddress:                  signerAddress,
				PyroscopeURL:                   pyroscopeURL,
				CommitteeVerifierAddresses:     filterAddressesByChains(committeeVerifierAddrs, nopChains),
				DefaultExecutorOnRampAddresses: filterAddressesByChains(executorOnRampAddrs, nopChains),
				DisableFinalityCheckers:        sortedFinalityCheckers,
				Monitoring:                     monitoring,
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses:    filterAddressesByChains(onRampAddrs, nopChains),
					RMNRemoteAddresses: filterAddressesByChains(rmnRemoteAddrs, nopChains),
				},
			}

			configBytes, err := toml.Marshal(verifierCfg)
			if err != nil {
				return nil, scope, fmt.Errorf("failed to marshal verifier config for NOP %q aggregator %q: %w", nopAlias, agg.Name, err)
			}

			jobID := verifierJobID.ToJobID()
			jobSpec := fmt.Sprintf(`schemaVersion = 1
type = "ccvcommitteeverifier"
name = "%s"
externalJobID = "%s"
committeeVerifierConfig = '''
%s'''
`, string(jobID), jobID.ToExternalJobID(), string(configBytes))

			if jobSpecs[nopAlias] == nil {
				jobSpecs[nopAlias] = make(map[shared.JobID]string)
			}
			jobSpecs[nopAlias][jobID] = jobSpec
		}
	}

	return jobSpecs, scope, nil
}

// fetchSigningKeysForNOPs fetches signing keys from JD for NOPs that are missing a signer
// address for the given signerFamily.
func fetchSigningKeysForNOPs(
	e deployment.Environment,
	nops []ccvdeployment.NOPConfig,
	signerFamily string,
) (fetch_signing_keys.SigningKeysByNOP, error) {
	return fetchSigningKeysForNOPsFiltered(e, nops, func(nop ccvdeployment.NOPConfig) bool {
		return nop.SignerAddressByFamily == nil || nop.SignerAddressByFamily[signerFamily] == ""
	})
}

func fetchSigningKeysForNOPsFiltered(
	e deployment.Environment,
	nops []ccvdeployment.NOPConfig,
	include func(ccvdeployment.NOPConfig) bool,
) (fetch_signing_keys.SigningKeysByNOP, error) {
	if e.Offchain == nil {
		return nil, nil
	}

	aliases := make([]string, 0, len(nops))
	for _, nop := range nops {
		if include(nop) {
			aliases = append(aliases, nop.Alias)
		}
	}

	if len(aliases) == 0 {
		return nil, nil
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
		return nil, fmt.Errorf("failed to fetch signing keys from JD for NOPs %v: %w", aliases, err)
	}

	return report.Output.SigningKeysByNOP, nil
}

func convertNOPsToVerifierInput(
	nops []ccvdeployment.NOPConfig,
	signingKeysByNOP fetch_signing_keys.SigningKeysByNOP,
	signerFamily string,
) []verifierNOPInput {
	result := make([]verifierNOPInput, len(nops))

	for i, nop := range nops {
		signerAddresses := nop.SignerAddressByFamily

		if signer, ok := signerFromJDIfMissing(signerAddresses, nop.Alias, signerFamily, signingKeysByNOP); ok {
			if signerAddresses == nil {
				signerAddresses = make(map[string]string)
			}
			signerAddresses[signerFamily] = signer
		}

		result[i] = verifierNOPInput{
			Alias:                 shared.NOPAlias(nop.Alias),
			SignerAddressByFamily: signerAddresses,
			Mode:                  nop.GetMode(),
		}
	}

	return result
}

func convertTopologyCommittee(committee ccvdeployment.CommitteeConfig) verifierCommitteeInput {
	aggregators := make([]verifierAggregatorInput, len(committee.Aggregators))
	for i, agg := range committee.Aggregators {
		aggregators[i] = verifierAggregatorInput{
			Name:                         agg.Name,
			Address:                      agg.Address,
			InsecureAggregatorConnection: agg.InsecureAggregatorConnection,
		}
	}

	chainNOPAliases := make(map[string][]shared.NOPAlias, len(committee.ChainConfigs))
	for chainSelector, chainConfig := range committee.ChainConfigs {
		chainNOPAliases[chainSelector] = shared.ConvertStringToNopAliases(chainConfig.NOPAliases)
	}

	return verifierCommitteeInput{
		Qualifier:       committee.Qualifier,
		Aggregators:     aggregators,
		NOPAliases:      shared.ConvertStringToNopAliases(getCommitteeNOPAliases(committee)),
		ChainNOPAliases: chainNOPAliases,
	}
}

func filterNOPsByAliases(nops []ccvdeployment.NOPConfig, aliases []string) []ccvdeployment.NOPConfig {
	aliasSet := make(map[string]struct{}, len(aliases))
	for _, a := range aliases {
		aliasSet[a] = struct{}{}
	}
	filtered := make([]ccvdeployment.NOPConfig, 0, len(aliases))
	for _, nop := range nops {
		if _, ok := aliasSet[nop.Alias]; ok {
			filtered = append(filtered, nop)
		}
	}
	return filtered
}

func getCommitteeNOPAliases(committee ccvdeployment.CommitteeConfig) []string {
	aliasSet := make(map[string]struct{})
	for _, chainConfig := range committee.ChainConfigs {
		for _, alias := range chainConfig.NOPAliases {
			aliasSet[alias] = struct{}{}
		}
	}
	aliases := make([]string, 0, len(aliasSet))
	for alias := range aliasSet {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	return aliases
}

func getCommitteeChainSelectors(committee ccvdeployment.CommitteeConfig) ([]uint64, error) {
	selectors := make([]uint64, 0, len(committee.ChainConfigs))
	for chainStr := range committee.ChainConfigs {
		sel, err := strconv.ParseUint(chainStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("committee chain_configs key %q is not a valid chain selector: %w", chainStr, err)
		}
		selectors = append(selectors, sel)
	}
	slices.Sort(selectors)
	return selectors, nil
}

func validateVerifierChainSupport(
	e deployment.Environment,
	nopsToValidate []shared.NOPAlias,
	committee ccvdeployment.CommitteeConfig,
) error {
	if e.Offchain == nil {
		e.Logger.Debugw("Offchain client not available, skipping chain support validation")
		return nil
	}

	nopAliasStrings := shared.ConvertNopAliasToString(nopsToValidate)

	supportedChains, err := fetchNodeChainSupport(e, nopAliasStrings)
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

func getRequiredChainsForNOP(nopAlias string, committee ccvdeployment.CommitteeConfig) ([]uint64, error) {
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

func signerFromJDIfMissing(
	signerAddresses map[string]string,
	nopAlias string,
	family string,
	signingKeysByNOP fetch_signing_keys.SigningKeysByNOP,
) (string, bool) {
	if signerAddresses != nil && signerAddresses[family] != "" {
		return "", false
	}

	if signingKeysByNOP == nil {
		return "", false
	}

	if signer := signingKeysByNOP[nopAlias][family]; signer != "" {
		return signer, true
	}

	return "", false
}

func getNOPChainMembership(nopAlias shared.NOPAlias, chainNOPAliases map[string][]shared.NOPAlias) map[string]bool {
	chains := make(map[string]bool)
	if chainNOPAliases == nil {
		return chains
	}
	for chainSelector, nops := range chainNOPAliases {
		if slices.Contains(nops, nopAlias) {
			chains[chainSelector] = true
		}
	}
	return chains
}

func filterAddressesByChains(addresses map[string]string, nopChains map[string]bool) map[string]string {
	if len(nopChains) == 0 {
		return addresses
	}
	filtered := make(map[string]string, len(nopChains))
	for chainSelector, addr := range addresses {
		if nopChains[chainSelector] {
			filtered[chainSelector] = addr
		}
	}
	return filtered
}
