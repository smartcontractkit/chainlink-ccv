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

// ApplyVerifierConfigInput is the imperative input for the ApplyVerifierConfig
// changeset. It replaces the prior topology-driven input — callers describe the
// committee, the participating NOPs, and any monitoring/profiling settings
// directly, without supplying a *EnvironmentTopology.
type ApplyVerifierConfigInput struct {
	// CommitteeQualifier identifies the committee being published.
	CommitteeQualifier string
	// DefaultExecutorQualifier resolves the per-chain executor proxy address that
	// gets baked into the verifier job spec.
	DefaultExecutorQualifier string
	// NOPs describes every NOP referenced by the committee. SignerAddressByFamily
	// is consulted first; missing entries fall back to a JD lookup.
	NOPs []NOPInput
	// Committee is the per-committee description: qualifier, aggregators, and
	// per-source-chain NOP membership.
	Committee CommitteeInput
	// PyroscopeURL is forwarded into the verifier job spec for profiling. Must be
	// empty in production environments (validated below).
	PyroscopeURL string
	// Monitoring is forwarded into the verifier job spec.
	Monitoring ccvdeployment.MonitoringConfig
	// TargetNOPs filters the publish set. Empty means "all NOPs in the committee".
	TargetNOPs []shared.NOPAlias
	// DisableFinalityCheckers lists chain-selector strings whose finality checks
	// should be skipped. Sorted before being baked into the job spec for stable
	// hashing.
	DisableFinalityCheckers []string
	// RevokeOrphanedJobs when true revokes and cleans up orphaned jobs; default false.
	RevokeOrphanedJobs bool
}

// ApplyVerifierConfig is the offchain-only single-entry product for §5.9 / §5.10:
// publish or refresh verifier job specs for a committee. It writes new job specs
// via JD (CL-mode NOPs) and persists job metadata into the DataStore. No onchain
// state is touched and no MCMS coordination is required.
//
// The input is imperative — callers pass the committee description and the
// participating NOPs directly, with no *EnvironmentTopology.
func ApplyVerifierConfig(registry *adapters.Registry) deployment.ChangeSetV2[ApplyVerifierConfigInput] {
	validate := func(e deployment.Environment, cfg ApplyVerifierConfigInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if cfg.DefaultExecutorQualifier == "" {
			return fmt.Errorf("default executor qualifier is required")
		}
		if cfg.Committee.Qualifier != "" && cfg.Committee.Qualifier != cfg.CommitteeQualifier {
			return fmt.Errorf(
				"committee qualifier mismatch: top-level %q vs Committee.Qualifier %q",
				cfg.CommitteeQualifier, cfg.Committee.Qualifier,
			)
		}
		if len(cfg.Committee.Aggregators) == 0 {
			return fmt.Errorf("at least one aggregator is required for committee %q", cfg.CommitteeQualifier)
		}
		if len(cfg.NOPs) == 0 {
			return fmt.Errorf("at least one NOP is required")
		}

		nopSet := make(map[shared.NOPAlias]bool, len(cfg.NOPs))
		for _, nop := range cfg.NOPs {
			if nop.Alias == "" {
				return fmt.Errorf("NOP alias is required")
			}
			if nopSet[nop.Alias] {
				return fmt.Errorf("duplicate NOP alias %q", nop.Alias)
			}
			nopSet[nop.Alias] = true
		}

		for chainSelector, chainCfg := range cfg.Committee.ChainConfigs {
			for _, alias := range chainCfg.NOPAliases {
				if !nopSet[alias] {
					return fmt.Errorf(
						"committee chain %d references unknown NOP alias %q",
						chainSelector, alias,
					)
				}
			}
		}

		for _, alias := range cfg.TargetNOPs {
			if !nopSet[alias] {
				return fmt.Errorf("NOP alias %q not found in NOPs", alias)
			}
		}

		if shared.IsProductionEnvironment(e.Name) && cfg.PyroscopeURL != "" {
			return fmt.Errorf("pyroscope URL is not supported for production environments")
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg ApplyVerifierConfigInput) (deployment.ChangesetOutput, error) {
		selectors, err := committeeChainSelectorsFromInput(cfg.Committee)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		if len(selectors) == 0 {
			return runOrphanJobCleanup(
				e,
				cfg.RevokeOrphanedJobs,
				shared.VerifierJobScope{CommitteeQualifier: cfg.CommitteeQualifier},
				map[string]string{"job_type": "verifier", "committee": cfg.CommitteeQualifier},
				buildNOPModes(cfg.NOPs),
				cfg.TargetNOPs,
				allNOPAliases(cfg.NOPs),
				"No chain configs found for committee, nothing to do",
				"No chain configs for committee, running orphan cleanup only",
				"committee", cfg.CommitteeQualifier,
			)
		}

		signerFamily, err := getSignerFamilyFromRegistry(registry, selectors)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to determine signer address family: %w", err)
		}

		nopsToValidate := cfg.TargetNOPs
		if len(nopsToValidate) == 0 {
			nopsToValidate = committeeNOPAliasesFromInput(cfg.Committee, cfg.NOPs)
		}

		targetedNOPs := filterNOPInputsByAliases(cfg.NOPs, nopsToValidate)
		signingKeysByNOP, err := fetchSigningKeysForNOPInputs(e, targetedNOPs, signerFamily)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to fetch signing keys: %w", err)
		}

		clNOPs := filterCLModeNOPs(nopsToValidate, cfg.NOPs)
		if err := validateVerifierChainSupport(e, clNOPs, cfg.Committee); err != nil {
			return deployment.ChangesetOutput{}, err
		}

		contractAddresses, err := buildVerifierContractConfigs(registry, e, selectors, cfg.CommitteeQualifier, cfg.DefaultExecutorQualifier)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		nopInputs := mergeSigningKeysIntoNOPInputs(cfg.NOPs, signingKeysByNOP, signerFamily)
		// Default Committee.Qualifier from CommitteeQualifier so VerifierJobScope
		// and downstream metadata are always non-empty. Validation already enforces
		// equality when both are set.
		committeeForBuild := cfg.Committee
		if committeeForBuild.Qualifier == "" {
			committeeForBuild.Qualifier = cfg.CommitteeQualifier
		}
		committeeInternal := toVerifierCommitteeInput(committeeForBuild, cfg.NOPs)

		jobSpecs, scope, err := buildVerifierJobSpecs(
			contractAddresses,
			cfg.TargetNOPs,
			nopInputs,
			committeeInternal,
			cfg.PyroscopeURL,
			cfg.Monitoring,
			cfg.DisableFinalityCheckers,
			signerFamily,
		)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		nopModes := buildNOPModes(cfg.NOPs)

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
					AllNOPs:    allNOPAliases(cfg.NOPs),
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

// AggregatorRef describes a single aggregator instance a verifier NOP connects to.
type AggregatorRef struct {
	Name                         string
	Address                      string
	InsecureAggregatorConnection bool
}

type verifierCommitteeInput struct {
	Qualifier       string
	Aggregators     []AggregatorRef
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

// fetchSigningKeysForNOPInputs fetches signing keys from JD for NOPs that are missing
// a signer address for the given signerFamily.
func fetchSigningKeysForNOPInputs(
	e deployment.Environment,
	nops []NOPInput,
	signerFamily string,
) (fetch_signing_keys.SigningKeysByNOP, error) {
	if e.Offchain == nil {
		return nil, nil
	}

	aliases := make([]string, 0, len(nops))
	for _, nop := range nops {
		if nop.SignerAddressByFamily == nil || nop.SignerAddressByFamily[signerFamily] == "" {
			aliases = append(aliases, string(nop.Alias))
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

// mergeSigningKeysIntoNOPInputs converts public NOPInput slices into the internal
// verifierNOPInput shape consumed by buildVerifierJobSpecs, filling in signer
// addresses fetched from JD when the caller did not supply them inline.
func mergeSigningKeysIntoNOPInputs(
	nops []NOPInput,
	signingKeysByNOP fetch_signing_keys.SigningKeysByNOP,
	signerFamily string,
) []verifierNOPInput {
	result := make([]verifierNOPInput, len(nops))
	for i, nop := range nops {
		signerAddresses := nop.SignerAddressByFamily
		if signer, ok := signerFromJDIfMissing(signerAddresses, string(nop.Alias), signerFamily, signingKeysByNOP); ok {
			if signerAddresses == nil {
				signerAddresses = make(map[string]string)
			}
			signerAddresses[signerFamily] = signer
		}
		result[i] = verifierNOPInput{
			Alias:                 nop.Alias,
			SignerAddressByFamily: signerAddresses,
			Mode:                  nop.GetMode(),
		}
	}
	return result
}

// toVerifierCommitteeInput converts the public CommitteeInput into the internal
// verifierCommitteeInput shape used by buildVerifierJobSpecs.
func toVerifierCommitteeInput(committee CommitteeInput, nops []NOPInput) verifierCommitteeInput {
	chainNOPAliases := make(map[string][]shared.NOPAlias, len(committee.ChainConfigs))
	for chainSelector, chainCfg := range committee.ChainConfigs {
		chainNOPAliases[strconv.FormatUint(chainSelector, 10)] = slices.Clone(chainCfg.NOPAliases)
	}

	return verifierCommitteeInput{
		Qualifier:       committee.Qualifier,
		Aggregators:     committee.Aggregators,
		NOPAliases:      committeeNOPAliasesFromInput(committee, nops),
		ChainNOPAliases: chainNOPAliases,
	}
}

// committeeNOPAliasesFromInput returns the union of NOP aliases referenced by the
// committee's chain configs. When ChainConfigs is empty the result falls back to
// every alias listed in nops — matching the per-NOP "all chains" behavior used
// by AddNOPOffchain's verifier-job provisioning.
func committeeNOPAliasesFromInput(committee CommitteeInput, nops []NOPInput) []shared.NOPAlias {
	if len(committee.ChainConfigs) == 0 {
		out := make([]shared.NOPAlias, len(nops))
		for i, nop := range nops {
			out[i] = nop.Alias
		}
		slices.Sort(out)
		return out
	}
	aliasSet := make(map[shared.NOPAlias]struct{})
	for _, chainCfg := range committee.ChainConfigs {
		for _, alias := range chainCfg.NOPAliases {
			aliasSet[alias] = struct{}{}
		}
	}
	out := make([]shared.NOPAlias, 0, len(aliasSet))
	for alias := range aliasSet {
		out = append(out, alias)
	}
	slices.Sort(out)
	return out
}

// committeeChainSelectorsFromInput extracts the sorted set of source-chain
// selectors the committee is configured for. Empty when no chain configs are set.
func committeeChainSelectorsFromInput(committee CommitteeInput) ([]uint64, error) {
	selectors := make([]uint64, 0, len(committee.ChainConfigs))
	for chainSelector := range committee.ChainConfigs {
		selectors = append(selectors, chainSelector)
	}
	slices.Sort(selectors)
	return selectors, nil
}

func filterNOPInputsByAliases(nops []NOPInput, aliases []shared.NOPAlias) []NOPInput {
	if len(aliases) == 0 {
		return slices.Clone(nops)
	}
	aliasSet := make(map[shared.NOPAlias]struct{}, len(aliases))
	for _, a := range aliases {
		aliasSet[a] = struct{}{}
	}
	filtered := make([]NOPInput, 0, len(aliases))
	for _, nop := range nops {
		if _, ok := aliasSet[nop.Alias]; ok {
			filtered = append(filtered, nop)
		}
	}
	return filtered
}

func validateVerifierChainSupport(
	e deployment.Environment,
	nopsToValidate []shared.NOPAlias,
	committee CommitteeInput,
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
		requiredChains := getRequiredChainsForVerifierNOP(nopAlias, committee)
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

func getRequiredChainsForVerifierNOP(nopAlias shared.NOPAlias, committee CommitteeInput) []uint64 {
	var requiredChains []uint64
	for chainSelector, chainCfg := range committee.ChainConfigs {
		if slices.Contains(chainCfg.NOPAliases, nopAlias) {
			requiredChains = append(requiredChains, chainSelector)
		}
	}
	slices.Sort(requiredChains)
	return requiredChains
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
