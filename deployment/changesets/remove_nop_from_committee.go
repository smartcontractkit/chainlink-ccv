package changesets

import (
	"context"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// RemoveNOPFromCommitteeInput is the input for step-1 of the RemoveNOP two-entry product.
type RemoveNOPFromCommitteeInput struct {
	// CommitteeQualifier identifies the committee the NOP is leaving.
	CommitteeQualifier string
	// SourceChainSelectors are the source chains for which the NOP's signer should be removed.
	// The changeset automatically updates every destination chain that has this committee
	// verifier deployed — callers do not enumerate dest chains.
	SourceChainSelectors []uint64
	// NOPAlias is the node alias used to look up the NOP's signing address in JD.
	NOPAlias string
	// NewThreshold is the desired threshold after the NOP is removed. Zero keeps the current threshold.
	// Must not exceed the remaining signer count.
	NewThreshold uint8
}

// RemoveNOPOffchainInput is the input for step-2 of the RemoveNOP two-entry product.
type RemoveNOPOffchainInput struct {
	// CommitteeQualifier identifies the committee.
	CommitteeQualifier string
	// SourceChainSelectors are the source chains updated in step-1. Must match step-1.
	SourceChainSelectors []uint64
	// RemovedSignerAddress is the signer address removed in step-1. If non-empty, validate
	// asserts this address is absent onchain on every dest chain for every source chain
	// before writing the new aggregator config — guarding against hook misfires or
	// out-of-order manual invocations where step-1 has not yet landed.
	RemovedSignerAddress string
	// ServiceIdentifiers lists every aggregator service that consumes this committee's config.
	// All are updated atomically in a single changeset run.
	ServiceIdentifiers []string
}

// RemoveNOPFromCommittee is step-1 of a coupled onchain-first two-entry product.
//
// It fetches the NOP's signing address from JD, then for every destination chain that has
// this committee verifier deployed (discovered automatically from the registry) it reads the
// current onchain committee state and submits an applySignatureConfigs call that removes the
// signer from each of the specified source chain configs. The aggregator config regen is
// deferred to RemoveNOPOffchain (step-2), which runs after the timelock executes via the CLD
// post-proposal hook.
//
// Onchain-first ordering is required because removing a signer from the contract immediately
// stops that signer's votes from being counted, while the aggregator still collects from
// them harmlessly until step-2 updates the offchain config.
func RemoveNOPFromCommittee(registry *adapters.Registry) deployment.ChangeSetV2[RemoveNOPFromCommitteeInput] {
	validate := func(e deployment.Environment, cfg RemoveNOPFromCommitteeInput) error {
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

	apply := func(e deployment.Environment, cfg RemoveNOPFromCommitteeInput) (deployment.ChangesetOutput, error) {
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
			change, err := buildRemoveSignerChange(committeeStates[sel], signerAddress, cfg.NewThreshold, cfg.SourceChainSelectors)
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

// RemoveNOPOffchain is step-2 of the RemoveNOP two-entry product.
//
// Validate asserts that the removed signer is absent onchain on every dest chain for every
// source chain listed in SourceChainSelectors (when RemovedSignerAddress is set). This guards
// against hook misfires or manual out-of-order invocations where step-1 has not yet landed.
//
// Apply regenerates the aggregator config from the updated onchain state and writes it to
// the DataStore for each listed service identifier. Dest chains are discovered automatically
// from the registry — the same set used by step-1.
//
// Note: JD verifier job revocation for the removed NOP is not yet implemented here.
// That requires the ApplyVerifierConfigForNOPs helper (Phase B open item).
func RemoveNOPOffchain(registry *adapters.Registry) deployment.ChangeSetV2[RemoveNOPOffchainInput] {
	validate := func(e deployment.Environment, cfg RemoveNOPOffchainInput) error {
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

		// Safety backstop: assert the removed signer is absent onchain on every dest chain for
		// every source chain. Catches hook misfires and out-of-order manual invocations.
		if cfg.RemovedSignerAddress != "" {
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
					for _, s := range sc.Signers {
						if strings.EqualFold(s, cfg.RemovedSignerAddress) {
							return fmt.Errorf(
								"dest chain %d source chain %d: signer %q still present onchain — step-1 (RemoveNOPFromCommittee) may not have been applied",
								destSel, sc.SourceChainSelector, cfg.RemovedSignerAddress,
							)
						}
					}
				}
			}
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg RemoveNOPOffchainInput) (deployment.ChangesetOutput, error) {
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

// buildRemoveSignerChange constructs a SignatureConfigChange that removes signerToRemove from
// every source chain config whose SourceChainSelector is in sourceChainSelectors. Configs for
// other source chains are left untouched (not included in NewConfigs).
//
// If newThreshold is non-zero it replaces the current threshold; otherwise the existing
// threshold is preserved, subject to not exceeding the remaining signer count.
func buildRemoveSignerChange(state *adapters.CommitteeState, signerToRemove string, newThreshold uint8, sourceChainSelectors []uint64) (adapters.SignatureConfigChange, error) {
	sourceSet := make(map[uint64]bool, len(sourceChainSelectors))
	for _, sel := range sourceChainSelectors {
		sourceSet[sel] = true
	}

	newConfigs := make([]adapters.SignatureConfig, 0, len(sourceChainSelectors))
	for _, sc := range state.SignatureConfigs {
		if !sourceSet[sc.SourceChainSelector] {
			continue
		}
		remaining := make([]string, 0, len(sc.Signers))
		found := false
		for _, s := range sc.Signers {
			if strings.EqualFold(s, signerToRemove) {
				found = true
				continue
			}
			remaining = append(remaining, s)
		}
		if !found {
			return adapters.SignatureConfigChange{}, fmt.Errorf(
				"source chain %d: signer %q not found in committee",
				sc.SourceChainSelector, signerToRemove,
			)
		}
		if len(remaining) == 0 {
			return adapters.SignatureConfigChange{}, fmt.Errorf(
				"source chain %d: cannot remove the last signer from a committee",
				sc.SourceChainSelector,
			)
		}
		threshold := sc.Threshold
		if newThreshold != 0 {
			threshold = newThreshold
		}
		if threshold > uint8(len(remaining)) {
			return adapters.SignatureConfigChange{}, fmt.Errorf(
				"source chain %d: threshold %d exceeds remaining signer count %d after removal",
				sc.SourceChainSelector, threshold, len(remaining),
			)
		}
		newConfigs = append(newConfigs, adapters.SignatureConfig{
			SourceChainSelector: sc.SourceChainSelector,
			Signers:             remaining,
			Threshold:           threshold,
		})
	}
	return adapters.SignatureConfigChange{NewConfigs: newConfigs}, nil
}
