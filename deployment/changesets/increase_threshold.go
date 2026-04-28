package changesets

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// IncreaseThresholdOffchainInput is the input for step-1 of the IncreaseThreshold two-entry product.
type IncreaseThresholdOffchainInput struct {
	// CommitteeQualifier identifies the committee whose threshold is being raised.
	CommitteeQualifier string
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// NewThreshold is the desired threshold. Must be greater than the current onchain threshold.
	NewThreshold uint8
	// ServiceIdentifiers lists every aggregator service that consumes this committee's config.
	// All are updated atomically in a single changeset run.
	ServiceIdentifiers []string
}

// IncreaseThresholdInput is the input for step-2 of the IncreaseThreshold two-entry product.
type IncreaseThresholdInput struct {
	// CommitteeQualifier identifies the committee whose threshold is being raised.
	CommitteeQualifier string
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// NewThreshold is the threshold to set onchain. Must be greater than the current onchain
	// threshold and must match the value used in step-1.
	NewThreshold uint8
	// ServiceIdentifiers lists every aggregator service that step-1 updated.
	// Used as a safety backstop: validate confirms each service's DataStore config already
	// reflects NewThreshold before the onchain change is submitted.
	ServiceIdentifiers []string
}

// IncreaseThresholdOffchain is step-1 of a coupled offchain-first two-entry product (§5.5).
//
// It regenerates the aggregator config with the new threshold without touching onchain state.
// The DataStore output is deployed to the aggregator service before step-2 runs.
//
// Offchain-first ordering is required because a higher threshold in the offchain config is a
// strict superset of the pre-change onchain requirements — over-signed messages are harmless
// until the onchain change catches up. Submitting the onchain change first would cause
// verifiers to accept bundles with fewer signers than the new offchain config requires,
// producing under-signed messages from the aggregator's perspective.
func IncreaseThresholdOffchain(registry *adapters.Registry) deployment.ChangeSetV2[IncreaseThresholdOffchainInput] {
	validate := func(e deployment.Environment, cfg IncreaseThresholdOffchainInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if cfg.NewThreshold == 0 {
			return fmt.Errorf("new threshold must be greater than zero")
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

		ctx := context.Background()
		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return err
		}
		return validateThresholdIncrease(committeeStates, cfg.NewThreshold, cfg.CommitteeQualifier)
	}

	apply := func(e deployment.Environment, cfg IncreaseThresholdOffchainInput) (deployment.ChangesetOutput, error) {
		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors, &cfg.NewThreshold)
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

		// No onchain output — the onchain change is deferred to step-2 (IncreaseThreshold),
		// which runs after the aggregator service has picked up the new config.
		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// IncreaseThreshold is step-2 of the IncreaseThreshold two-entry product (§5.5).
//
// It submits the onchain applySignatureConfigs call only. Validate enforces two
// preconditions before allowing the onchain mutation:
//
//  1. Every service identifier's DataStore aggregator config already reflects NewThreshold,
//     confirming step-1 (IncreaseThresholdOffchain) has been deployed and nodes are
//     collecting signatures at the new quorum. Without this guard the onchain change could
//     fire while aggregators are still producing bundles signed at the old threshold,
//     making them invalid against the updated contract.
//  2. The current onchain threshold is still below NewThreshold, guarding against
//     double-fires and out-of-order manual invocations.
//
// In deployer-key mode the transaction is submitted directly inside Apply.
// MCMS-mode support is deferred to Phase 0 (CLD post-proposal hook prerequisite).
func IncreaseThreshold(registry *adapters.Registry) deployment.ChangeSetV2[IncreaseThresholdInput] {
	validate := func(e deployment.Environment, cfg IncreaseThresholdInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if cfg.NewThreshold == 0 {
			return fmt.Errorf("new threshold must be greater than zero")
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
		}

		// Safety backstop 1: assert every aggregator's DataStore config already reflects
		// NewThreshold. This confirms step-1 has been deployed and nodes are collecting
		// signatures at the new quorum before the contract enforces it. Without this guard,
		// the onchain change could fire while aggregators are still producing bundles signed
		// at the old (lower) threshold, making them invalid.
		if e.DataStore != nil {
			for _, svcID := range cfg.ServiceIdentifiers {
				committee, err := ccvdeployment.GetAggregatorConfig(e.DataStore, svcID)
				if err != nil {
					return fmt.Errorf("aggregator config for %q not found in DataStore — step-1 (IncreaseThresholdOffchain) may not have been deployed: %w", svcID, err)
				}
				for chainSel, qc := range committee.QuorumConfigs {
					if qc.Threshold != cfg.NewThreshold {
						return fmt.Errorf(
							"aggregator %q chain %s: DataStore threshold %d does not match expected %d — step-1 (IncreaseThresholdOffchain) may not have been deployed yet",
							svcID, chainSel, qc.Threshold, cfg.NewThreshold,
						)
					}
				}
			}
		}

		// Safety backstop 2: assert the onchain threshold has not yet been raised to
		// NewThreshold. Catches double-fires and out-of-order manual invocations.
		ctx := context.Background()
		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return err
		}
		return validateThresholdIncrease(committeeStates, cfg.NewThreshold, cfg.CommitteeQualifier)
	}

	apply := func(e deployment.Environment, cfg IncreaseThresholdInput) (deployment.ChangesetOutput, error) {
		ctx := context.Background()

		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		for _, sel := range cfg.ChainSelectors {
			change, err := buildSignatureConfigChange(committeeStates[sel], cfg.NewThreshold)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: failed to build signature config change: %w", sel, err)
			}

			a, _ := registry.GetByChain(sel)
			if err := a.CommitteeVerifierOnchain.ApplySignatureConfigs(ctx, e, sel, cfg.CommitteeQualifier, change); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: ApplySignatureConfigs failed: %w", sel, err)
			}
		}

		// No DataStore output — aggregator config was already written in step-1.
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// scanCommitteeStatesForChains returns the CommitteeState for the given qualifier on
// each chain, keyed by chain selector.
func scanCommitteeStatesForChains(
	ctx context.Context,
	e deployment.Environment,
	registry *adapters.Registry,
	qualifier string,
	chainSelectors []uint64,
) (map[uint64]*adapters.CommitteeState, error) {
	result := make(map[uint64]*adapters.CommitteeState, len(chainSelectors))
	for _, sel := range chainSelectors {
		a, err := registry.GetByChain(sel)
		if err != nil {
			return nil, fmt.Errorf("chain %d: %w", sel, err)
		}
		states, err := a.CommitteeVerifierOnchain.ScanCommitteeStates(ctx, e, sel)
		if err != nil {
			return nil, fmt.Errorf("chain %d: ScanCommitteeStates failed: %w", sel, err)
		}
		var found *adapters.CommitteeState
		for _, s := range states {
			if s.Qualifier == qualifier {
				found = s
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("chain %d: committee %q not found in deployed verifier state", sel, qualifier)
		}
		result[sel] = found
	}
	return result, nil
}

// buildSignatureConfigChange constructs a SignatureConfigChange that keeps the existing
// signers but replaces the threshold with newThreshold.
func buildSignatureConfigChange(state *adapters.CommitteeState, newThreshold uint8) (adapters.SignatureConfigChange, error) {
	newConfigs := make([]adapters.SignatureConfig, 0, len(state.SignatureConfigs))
	for _, sc := range state.SignatureConfigs {
		newConfigs = append(newConfigs, adapters.SignatureConfig{
			SourceChainSelector: sc.SourceChainSelector,
			Signers:             sc.Signers,
			Threshold:           newThreshold,
		})
	}
	return adapters.SignatureConfigChange{NewConfigs: newConfigs}, nil
}

// validateThresholdIncrease returns an error if newThreshold is not strictly greater
// than the current threshold on every chain, or if it exceeds the signer count.
func validateThresholdIncrease(
	states map[uint64]*adapters.CommitteeState,
	newThreshold uint8,
	qualifier string,
) error {
	for sel, state := range states {
		for _, sc := range state.SignatureConfigs {
			if newThreshold <= sc.Threshold {
				return fmt.Errorf(
					"chain %d source %d: new threshold %d is not greater than current threshold %d",
					sel, sc.SourceChainSelector, newThreshold, sc.Threshold,
				)
			}
			if int(newThreshold) > len(sc.Signers) {
				return fmt.Errorf(
					"chain %d source %d: new threshold %d exceeds signer count %d",
					sel, sc.SourceChainSelector, newThreshold, len(sc.Signers),
				)
			}
		}
	}
	return nil
}
