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
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
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
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// ServiceIdentifiers lists every aggregator service that consumes this committee's config.
	// All are updated atomically in a single changeset run.
	ServiceIdentifiers []string
}

// RemoveNOPFromCommittee is step-1 of a coupled onchain-first two-entry product.
//
// It fetches the NOP's signing address from JD, reads the current onchain committee state,
// and submits an applySignatureConfigs call that removes the signer. The aggregator config
// regen is deferred to RemoveNOPOffchain (step-2), which runs after the timelock executes
// via the CLD post-proposal hook.
//
// Onchain-first ordering is safe because removing a signer from the contract immediately
// stops that signer's votes from being counted, while the aggregator still collects from
// them harmlessly until step-2 updates the offchain config.
func RemoveNOPFromCommittee(registry *adapters.Registry) deployment.ChangeSetV2[RemoveNOPFromCommitteeInput] {
	validate := func(e deployment.Environment, cfg RemoveNOPFromCommitteeInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if cfg.NOPAlias == "" {
			return fmt.Errorf("NOP alias is required")
		}
		for _, sel := range cfg.ChainSelectors {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return fmt.Errorf("chain %d: %w", sel, err)
			}
			if a.CommitteeVerifierOnchain == nil {
				return fmt.Errorf("chain %d: no CommitteeVerifierOnchain adapter registered", sel)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg RemoveNOPFromCommitteeInput) (deployment.ChangesetOutput, error) {
		ctx := context.Background()

		signerFamily, err := getSignerFamilyFromRegistry(registry, cfg.ChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		signerAddress, err := fetchSignerAddress(e, cfg.NOPAlias, signerFamily)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		for _, sel := range cfg.ChainSelectors {
			change, err := buildRemoveSignerChange(committeeStates[sel], signerAddress, cfg.NewThreshold)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: %w", sel, err)
			}
			a, _ := registry.GetByChain(sel)
			if err := a.CommitteeVerifierOnchain.ApplySignatureConfigs(ctx, e, sel, cfg.CommitteeQualifier, change); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: ApplySignatureConfigs failed: %w", sel, err)
			}
		}

		// No DataStore output — aggregator config regen is deferred to step-2.
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// RemoveNOPOffchain is step-2 of the RemoveNOP two-entry product.
//
// It regenerates the aggregator config from the updated onchain state (which no longer
// includes the removed signer) and writes it to the DataStore for each listed service
// identifier. Triggered by the CLD post-proposal hook after timelock execution.
func RemoveNOPOffchain(registry *adapters.Registry) deployment.ChangeSetV2[RemoveNOPOffchainInput] {
	validate := func(e deployment.Environment, cfg RemoveNOPOffchainInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if len(cfg.ServiceIdentifiers) == 0 {
			return fmt.Errorf("at least one service identifier is required")
		}
		for _, sel := range cfg.ChainSelectors {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return fmt.Errorf("chain %d: %w", sel, err)
			}
			if a.CommitteeVerifierOnchain == nil {
				return fmt.Errorf("chain %d: no CommitteeVerifierOnchain adapter registered", sel)
			}
			if a.Aggregator == nil {
				return fmt.Errorf("chain %d: no Aggregator adapter registered", sel)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg RemoveNOPOffchainInput) (deployment.ChangesetOutput, error) {
		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors, nil)
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

// buildRemoveSignerChange constructs a SignatureConfigChange that removes signerToRemove
// from every source chain config. If newThreshold is non-zero it replaces the current
// threshold; otherwise the existing threshold is preserved, subject to not exceeding the
// remaining signer count.
func buildRemoveSignerChange(state *adapters.CommitteeState, signerToRemove string, newThreshold uint8) (adapters.SignatureConfigChange, error) {
	newConfigs := make([]adapters.SignatureConfig, 0, len(state.SignatureConfigs))
	for _, sc := range state.SignatureConfigs {
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
