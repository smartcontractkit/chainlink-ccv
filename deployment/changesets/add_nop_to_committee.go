package changesets

// AddNOP two-entry product overview
//
// Adding a NOP to a committee is a coupled, onchain-first operation split across two
// changesets that must run in order:
//
//  1. AddNOPToCommittee (step-1, onchain) — fetches the new NOP's signing address from JD,
//     reads the current committee state on every dest chain that has this committee
//     verifier deployed (auto-discovered from the registry), and submits an
//     applySignatureConfigs call that appends the new signer to each of the specified
//     source chain configs. No offchain state is touched.
//
//  2. AddNOPOffchain (step-2, offchain) — re-reads the now-updated onchain committee
//     state, regenerates the aggregator config, and writes it to the DataStore for every
//     listed service identifier. In the same run, verifier jobs for the new NOP are
//     provisioned via JD. Validate optionally backstops the ordering by asserting the new
//     signer is already onchain (when ExpectedSignerAddress is set), guarding against
//     hook misfires or out-of-order manual invocations.
//
// Onchain-first ordering is safe for an add: the existing signers already satisfy the
// current threshold, so appending a new signer cannot raise the quorum requirement.
//
// In CLD, step-2 is wired as a post-proposal hook on step-1's MCMS proposal so it runs
// automatically after timelock execution. Outside of CLD (e.g. devenv), the caller is
// responsible for invoking step-2 once step-1's transactions have landed onchain.
//
// Both steps assume CL mode: signer addresses are fetched from JD by NOPAlias and
// verifier jobs are managed via JD job proposals. Standalone-NOP support is a follow-up;
// it would require an alternate signer-address source (e.g. supplied directly in the
// input) and a different job-management path that does not depend on JD.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_signing_keys"
	"github.com/smartcontractkit/chainlink-ccv/deployment/sequences"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// Job proposal label keys/values shared across NOP-management changesets.
const (
	jobLabelKeyJobType    = "job_type"
	jobLabelKeyCommittee  = "committee"
	jobLabelValueVerifier = "verifier"
)

// AddNOPToCommitteeInput is the input for step-1 of the AddNOP two-entry product.
type AddNOPToCommitteeInput struct {
	// CommitteeQualifier identifies the committee the NOP is joining.
	CommitteeQualifier string
	// SourceChainSelectors are the source chains for which the NOP will sign attestations.
	// The changeset automatically updates every destination chain that has this committee
	// verifier deployed — callers do not enumerate dest chains.
	SourceChainSelectors []uint64
	// NOPAlias is the node alias used to look up the NOP's signing address in JD.
	NOPAlias string
	// NewThreshold is the desired threshold after the NOP is added. Zero keeps the current threshold.
	NewThreshold uint8
}

// AddNOPOffchainInput is the input for step-2 of the AddNOP two-entry product.
type AddNOPOffchainInput struct {
	// CommitteeQualifier identifies the committee.
	CommitteeQualifier string
	// SourceChainSelectors are the source chains updated in step-1. Must match step-1.
	SourceChainSelectors []uint64
	// ExpectedSignerAddress is the signer address added in step-1. If non-empty, validate
	// asserts this address is present onchain on every dest chain for every source chain
	// before writing the new aggregator config — guarding against hook misfires or
	// out-of-order manual invocations where step-1 has not yet landed.
	ExpectedSignerAddress string
	// ServiceIdentifiers lists every aggregator service that consumes this committee's config.
	// All are updated atomically in a single changeset run.
	ServiceIdentifiers []string
	// NOPAlias is the alias of the NOP whose verifier jobs should be provisioned.
	NOPAlias shared.NOPAlias
	// Aggregators lists the aggregator instances the NOP's verifier jobs should connect to.
	Aggregators []AggregatorRef
	// ExecutorQualifier is used to resolve executor contract addresses for job spec generation.
	ExecutorQualifier string
	// DisableFinalityCheckers is a list of chain selectors for which finality checks are disabled.
	DisableFinalityCheckers []string
	// Monitoring holds monitoring configuration included in the job spec.
	Monitoring ccvdeployment.MonitoringConfig
}

// AddNOPToCommittee is step-1 of a coupled onchain-first two-entry product.
//
// It fetches the NOP's signing address from JD, then for every destination chain that has
// this committee verifier deployed (discovered automatically from the registry) it reads the
// current onchain committee state and submits an applySignatureConfigs call that appends the
// new signer to each of the specified source chain configs. The aggregator config regen is
// deferred to AddNOPOffchain (step-2), which runs after the timelock executes via the CLD
// post-proposal hook.
//
// Onchain-first ordering is safe because adding a new signer does not raise the quorum
// requirement — the existing signers already satisfy the current threshold.
func AddNOPToCommittee(registry *adapters.Registry) deployment.ChangeSetV2[AddNOPToCommitteeInput] {
	validate := func(e deployment.Environment, cfg AddNOPToCommitteeInput) error {
		return validateStep1NOP(e, cfg.CommitteeQualifier, cfg.NOPAlias, cfg.SourceChainSelectors, registry)
	}

	apply := func(e deployment.Environment, cfg AddNOPToCommitteeInput) (deployment.ChangesetOutput, error) {
		signerFamily, err := getSignerFamilyFromRegistry(registry, cfg.SourceChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}
		if err := applySignerChangesOnchain(e, registry, cfg.CommitteeQualifier, cfg.NOPAlias, signerFamily,
			cfg.SourceChainSelectors, cfg.NewThreshold, buildAddSignerChange); err != nil {
			return deployment.ChangesetOutput{}, err
		}
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// validateStep1NOP is the shared validation for the step-1 onchain changesets (AddNOPToCommittee
// and RemoveNOPFromCommittee).
func validateStep1NOP(e deployment.Environment, qualifier, nopAlias string, sourceChainSelectors []uint64, registry *adapters.Registry) error {
	if e.Offchain == nil {
		return fmt.Errorf("offchain client is required")
	}
	if qualifier == "" {
		return fmt.Errorf("committee qualifier is required")
	}
	if len(sourceChainSelectors) == 0 {
		return fmt.Errorf("at least one source chain selector is required")
	}
	if nopAlias == "" {
		return fmt.Errorf("NOP alias is required")
	}
	if _, err := getSignerFamilyFromRegistry(registry, sourceChainSelectors); err != nil {
		return err
	}
	return nil
}

// applySignerChangesOnchain is the shared apply core of AddNOPToCommittee and
// RemoveNOPFromCommittee. It fetches the signer address, scans every deployed dest chain for the
// committee, builds the change via buildChange, and submits an ApplySignatureConfigs call.
func applySignerChangesOnchain(
	e deployment.Environment,
	registry *adapters.Registry,
	committeeQualifier string,
	nopAlias string,
	signerFamily string,
	sourceChainSelectors []uint64,
	newThreshold uint8,
	buildChange func(*adapters.CommitteeState, string, uint8, []uint64) (adapters.SignatureConfigChange, error),
) error {
	ctx := e.GetContext()

	signerAddress, err := fetchSignerAddress(e, nopAlias, signerFamily)
	if err != nil {
		return err
	}

	committeeChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, committeeQualifier)
	if len(committeeChains) == 0 {
		return fmt.Errorf(
			"no dest chains found with committee verifier for qualifier %q — ensure adapters are registered and the committee is deployed",
			committeeQualifier,
		)
	}

	committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, committeeQualifier, committeeChains)
	if err != nil {
		return err
	}

	applied := 0
	for _, sel := range committeeChains {
		change, buildErr := buildChange(committeeStates[sel], signerAddress, newThreshold, sourceChainSelectors)
		if buildErr != nil {
			return fmt.Errorf("dest chain %d: %w", sel, buildErr)
		}
		if len(change.NewConfigs) == 0 {
			continue // this dest chain has no configs for the requested source chains
		}
		a, _ := registry.GetByChain(sel)
		if applyErr := a.CommitteeVerifierOnchain.ApplySignatureConfigs(ctx, e, sel, committeeQualifier, change); applyErr != nil {
			return fmt.Errorf("dest chain %d: ApplySignatureConfigs failed: %w", sel, applyErr)
		}
		applied++
	}

	if applied == 0 {
		return fmt.Errorf(
			"no dest chain had source chain configs for selectors %v in committee %q — verify the committee is deployed and source chains are configured",
			sourceChainSelectors, committeeQualifier,
		)
	}
	return nil
}

// AddNOPOffchain is step-2 of the AddNOP two-entry product.
//
// Validate asserts that the new signer is already present onchain on every dest chain for
// every source chain listed in SourceChainSelectors (when ExpectedSignerAddress is set).
// This guards against hook misfires or manual out-of-order invocations where step-1 has not
// yet executed.
//
// Apply regenerates the aggregator config from the updated onchain state and writes it to
// the DataStore for each listed service identifier. Dest chains are discovered automatically
// from the registry — the same set used by step-1.
//
// When NOPAlias and Aggregators are both set, verifier jobs are provisioned for the new NOP
// via JD in the same run. The signer address is taken from ExpectedSignerAddress if set,
// otherwise fetched from JD.
func AddNOPOffchain(registry *adapters.Registry) deployment.ChangeSetV2[AddNOPOffchainInput] {
	validate := func(e deployment.Environment, cfg AddNOPOffchainInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.SourceChainSelectors) == 0 {
			return fmt.Errorf("at least one source chain selector is required")
		}
		if len(cfg.ServiceIdentifiers) == 0 {
			return fmt.Errorf("at least one service identifier is required")
		}
		if cfg.NOPAlias == "" {
			return fmt.Errorf("NOP alias is required for job provisioning")
		}
		if len(cfg.Aggregators) == 0 {
			return fmt.Errorf("at least one aggregator is required for job provisioning")
		}
		if cfg.ExecutorQualifier == "" {
			return fmt.Errorf("executor qualifier is required for job provisioning")
		}

		committeeChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, cfg.CommitteeQualifier)
		if len(committeeChains) == 0 {
			return fmt.Errorf("no dest chains found for committee %q — step-1 may not have been applied or adapters are not registered", cfg.CommitteeQualifier)
		}
		for _, sel := range committeeChains {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return fmt.Errorf("dest chain %d: %w", sel, err)
			}
			if a.CommitteeVerifierOnchain == nil {
				return fmt.Errorf("dest chain %d: no CommitteeVerifierOnchain adapter registered", sel)
			}
			if a.Aggregator == nil {
				return fmt.Errorf("dest chain %d: no Aggregator adapter registered", sel)
			}
		}

		// Safety backstop: assert the new signer is present onchain on every dest chain for
		// every source chain. Catches hook misfires and out-of-order manual invocations.
		if cfg.ExpectedSignerAddress != "" {
			committeeStates, err := scanCommitteeStatesForChains(e.GetContext(), e, registry, cfg.CommitteeQualifier, committeeChains)
			if err != nil {
				return err
			}
			sourceSet := make(map[uint64]bool, len(cfg.SourceChainSelectors))
			for _, sel := range cfg.SourceChainSelectors {
				sourceSet[sel] = true
			}
			for destSel, state := range committeeStates {
				for _, sc := range state.SignatureConfigs {
					if !sourceSet[sc.SourceChainSelector] {
						continue
					}
					found := false
					for _, s := range sc.Signers {
						if strings.EqualFold(s, cfg.ExpectedSignerAddress) {
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf(
							"dest chain %d source chain %d: signer %q not found onchain — step-1 (AddNOPToCommittee) may not have been applied",
							destSel, sc.SourceChainSelector, cfg.ExpectedSignerAddress,
						)
					}
				}
			}
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg AddNOPOffchainInput) (deployment.ChangesetOutput, error) {
		committeeChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, cfg.CommitteeQualifier)
		if len(committeeChains) == 0 {
			return deployment.ChangesetOutput{}, fmt.Errorf("no dest chains found for committee %q", cfg.CommitteeQualifier)
		}

		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, committeeChains, nil)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to build aggregator config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge datastore: %w", err)
			}
		}
		for _, svcID := range cfg.ServiceIdentifiers {
			if err := ccvdeployment.SaveAggregatorConfig(outputDS, svcID, committee); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to save aggregator config for %q: %w", svcID, err)
			}
		}

		manageDS, reports, err := provisionVerifierJobForNOP(e, registry, cfg, committeeChains, outputDS.Seal())
		if err != nil {
			return deployment.ChangesetOutput{Reports: reports}, err
		}
		return deployment.ChangesetOutput{Reports: reports, DataStore: manageDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// provisionVerifierJobForNOP builds verifier job specs for the single NOP being added and
// runs ManageJobProposals against a datastore that already contains the updated aggregator
// config. The returned MutableDataStore carries both the aggregator config changes and the
// new job metadata.
func provisionVerifierJobForNOP(
	e deployment.Environment,
	registry *adapters.Registry,
	cfg AddNOPOffchainInput,
	committeeChains []uint64,
	baseDS datastore.DataStore,
) (datastore.MutableDataStore, []operations.Report[any, any], error) {
	signerFamily, err := getSignerFamilyFromRegistry(registry, cfg.SourceChainSelectors)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine signer family for job provisioning: %w", err)
	}

	signerAddress := cfg.ExpectedSignerAddress
	if signerAddress == "" {
		addr, err := fetchSignerAddress(e, string(cfg.NOPAlias), signerFamily)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch signer address for job provisioning: %w", err)
		}
		signerAddress = addr
	}

	contractAddresses, err := buildVerifierContractConfigs(registry, e, committeeChains, cfg.CommitteeQualifier, cfg.ExecutorQualifier)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build verifier contract configs: %w", err)
	}

	nopInputs := []verifierNOPInput{{
		Alias:                 cfg.NOPAlias,
		SignerAddressByFamily: map[string]string{signerFamily: signerAddress},
		Mode:                  shared.NOPModeCL,
	}}
	committeeInput := verifierCommitteeInput{
		Qualifier:   cfg.CommitteeQualifier,
		Aggregators: cfg.Aggregators,
		NOPAliases:  []shared.NOPAlias{cfg.NOPAlias},
		// ChainNOPAliases is nil → NOP participates on all chains.
	}

	jobSpecs, scope, err := buildVerifierJobSpecs(
		contractAddresses,
		[]shared.NOPAlias{cfg.NOPAlias},
		nopInputs,
		committeeInput,
		"",
		cfg.Monitoring,
		cfg.DisableFinalityCheckers,
		signerFamily,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build verifier job specs: %w", err)
	}

	// Use baseDS (which contains the updated aggregator config) as the starting point so
	// ManageJobProposals' output DataStore carries both aggregator changes and job metadata.
	envWithBase := e
	envWithBase.DataStore = baseDS

	manageReport, err := operations.ExecuteSequence(
		e.OperationsBundle,
		sequences.ManageJobProposals,
		sequences.ManageJobProposalsDeps{Env: envWithBase},
		sequences.ManageJobProposalsInput{
			JobSpecs:      jobSpecs,
			AffectedScope: scope,
			Labels: map[string]string{
				jobLabelKeyJobType:   jobLabelValueVerifier,
				jobLabelKeyCommittee: cfg.CommitteeQualifier,
			},
			NOPs: sequences.NOPContext{
				Modes:      map[shared.NOPAlias]shared.NOPMode{cfg.NOPAlias: shared.NOPModeCL},
				TargetNOPs: []shared.NOPAlias{cfg.NOPAlias},
				AllNOPs:    []shared.NOPAlias{cfg.NOPAlias},
			},
			RevokeOrphanedJobs: false,
		},
	)
	if err != nil {
		return nil, manageReport.ExecutionReports, fmt.Errorf("failed to manage job proposals: %w", err)
	}

	e.Logger.Infow("Verifier jobs provisioned for NOP",
		"nopAlias", cfg.NOPAlias,
		"jobCount", len(manageReport.Output.Jobs),
		"committee", cfg.CommitteeQualifier,
	)

	return manageReport.Output.DataStore, manageReport.ExecutionReports, nil
}

// fetchSignerAddress fetches the onchain signing address for a single NOP alias from JD.
func fetchSignerAddress(e deployment.Environment, nopAlias, signerFamily string) (string, error) {
	if e.Offchain == nil {
		return "", fmt.Errorf("offchain client not available — cannot fetch signer address for NOP %q", nopAlias)
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
			NOPAliases: []string{nopAlias},
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to fetch signing keys for NOP %q: %w", nopAlias, err)
	}

	addr := report.Output.SigningKeysByNOP[nopAlias][signerFamily]
	if addr == "" {
		return "", fmt.Errorf("no signer address found in JD for NOP %q family %s", nopAlias, signerFamily)
	}
	return addr, nil
}

// buildAddSignerChange constructs a SignatureConfigChange that appends newSigner to every
// source chain config whose SourceChainSelector is in sourceChainSelectors. Configs for
// other source chains are left untouched (not included in NewConfigs).
//
// If newThreshold is non-zero it replaces the current threshold; otherwise the existing
// threshold is preserved.
func buildAddSignerChange(state *adapters.CommitteeState, newSigner string, newThreshold uint8, sourceChainSelectors []uint64) (adapters.SignatureConfigChange, error) {
	sourceSet := make(map[uint64]bool, len(sourceChainSelectors))
	for _, sel := range sourceChainSelectors {
		sourceSet[sel] = true
	}

	newConfigs := make([]adapters.SignatureConfig, 0, len(sourceChainSelectors))
	for _, sc := range state.SignatureConfigs {
		if !sourceSet[sc.SourceChainSelector] {
			continue
		}
		for _, s := range sc.Signers {
			if strings.EqualFold(s, newSigner) {
				return adapters.SignatureConfigChange{}, fmt.Errorf(
					"source chain %d: signer %q is already a committee member",
					sc.SourceChainSelector, newSigner,
				)
			}
		}
		threshold := sc.Threshold
		if newThreshold != 0 {
			threshold = newThreshold
		}
		newSignerCount := len(sc.Signers) + 1
		if threshold == 0 || int(threshold) > newSignerCount {
			return adapters.SignatureConfigChange{}, fmt.Errorf(
				"source chain %d: invalid threshold %d for %d signers after adding signer %q",
				sc.SourceChainSelector, threshold, newSignerCount, newSigner,
			)
		}
		newConfigs = append(newConfigs, adapters.SignatureConfig{
			SourceChainSelector: sc.SourceChainSelector,
			Signers:             append(slices.Clone(sc.Signers), newSigner),
			Threshold:           threshold,
		})
	}
	return adapters.SignatureConfigChange{NewConfigs: newConfigs}, nil
}
