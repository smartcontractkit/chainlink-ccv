package changesets

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_signing_keys"
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
		if e.Offchain == nil {
			return fmt.Errorf("offchain client is required")
		}
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.SourceChainSelectors) == 0 {
			return fmt.Errorf("at least one source chain selector is required")
		}
		if cfg.NOPAlias == "" {
			return fmt.Errorf("NOP alias is required")
		}
		// Validate all source chains belong to the same signing family.
		if _, err := getSignerFamilyFromRegistry(registry, cfg.SourceChainSelectors); err != nil {
			return err
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg AddNOPToCommitteeInput) (deployment.ChangesetOutput, error) {
		ctx := context.Background()

		signerFamily, err := getSignerFamilyFromRegistry(registry, cfg.SourceChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		signerAddress, err := fetchSignerAddress(e, cfg.NOPAlias, signerFamily)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		destChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, cfg.CommitteeQualifier)
		if len(destChains) == 0 {
			return deployment.ChangesetOutput{}, fmt.Errorf(
				"no dest chains found with committee verifier for qualifier %q — ensure adapters are registered and the committee is deployed",
				cfg.CommitteeQualifier,
			)
		}

		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, destChains)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		applied := 0
		for _, sel := range destChains {
			change, err := buildAddSignerChange(committeeStates[sel], signerAddress, cfg.NewThreshold, cfg.SourceChainSelectors)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("dest chain %d: %w", sel, err)
			}
			if len(change.NewConfigs) == 0 {
				continue // this dest chain has no configs for the requested source chains
			}
			a, _ := registry.GetByChain(sel)
			if err := a.CommitteeVerifierOnchain.ApplySignatureConfigs(ctx, e, sel, cfg.CommitteeQualifier, change); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("dest chain %d: ApplySignatureConfigs failed: %w", sel, err)
			}
			applied++
		}

		if applied == 0 {
			return deployment.ChangesetOutput{}, fmt.Errorf(
				"no dest chain had source chain configs for selectors %v in committee %q — verify the committee is deployed and source chains are configured",
				cfg.SourceChainSelectors, cfg.CommitteeQualifier,
			)
		}

		// No DataStore output — aggregator config regen is deferred to step-2.
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
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
// Note: JD verifier job provisioning for the new NOP is not yet implemented here.
// That requires the ApplyVerifierConfigForNOPs helper (Phase B open item).
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

		destChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, cfg.CommitteeQualifier)
		if len(destChains) == 0 {
			return fmt.Errorf("no dest chains found for committee %q — step-1 may not have been applied or adapters are not registered", cfg.CommitteeQualifier)
		}
		for _, sel := range destChains {
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
			ctx := context.Background()
			committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, destChains)
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
		destChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, cfg.CommitteeQualifier)
		if len(destChains) == 0 {
			return deployment.ChangesetOutput{}, fmt.Errorf("no dest chains found for committee %q", cfg.CommitteeQualifier)
		}

		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, destChains, nil)
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

		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// fetchSignerAddress fetches the onchain signing address for a single NOP alias from JD.
func fetchSignerAddress(e deployment.Environment, nopAlias string, signerFamily string) (string, error) {
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
