package changesets

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// DecreaseThresholdInput is the input for step-1 of the DecreaseThreshold two-entry product.
type DecreaseThresholdInput struct {
	// CommitteeQualifier identifies the committee whose threshold is being lowered.
	CommitteeQualifier string
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// NewThreshold is the desired threshold. Must be less than the current onchain threshold
	// and greater than zero.
	NewThreshold uint8
}

// DecreaseThreshold is step-1 of a coupled onchain-first two-entry product (§5.6).
//
// It submits the onchain applySignatureConfigs call only. The offchain aggregator config
// regen is deferred to DecreaseThresholdOffchain (step-2), which runs after the timelock
// executes via the CLD post-proposal hook.
//
// Onchain-first ordering is required because lowering the threshold offchain first would
// cause verifiers to sign with the smaller quorum while onchain still requires the larger
// one, producing under-signed messages.
//
// In deployer-key mode the transaction is submitted directly inside Apply.
// MCMS-mode support is deferred to Phase 0 (CLD post-proposal hook prerequisite).
func DecreaseThreshold(registry *adapters.Registry) deployment.ChangeSetV2[DecreaseThresholdInput] {
	validate := func(e deployment.Environment, cfg DecreaseThresholdInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if cfg.NewThreshold == 0 {
			return fmt.Errorf("new threshold must be greater than zero")
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

	apply := func(e deployment.Environment, cfg DecreaseThresholdInput) (deployment.ChangesetOutput, error) {
		ctx := context.Background()

		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		if err := validateThresholdDecrease(committeeStates, cfg.NewThreshold, cfg.CommitteeQualifier); err != nil {
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

		// No DataStore output — offchain aggregator regen is deferred to step-2.
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// DecreaseThresholdOffchainInput is the input for step-2 of the DecreaseThreshold product.
type DecreaseThresholdOffchainInput struct {
	// CommitteeQualifier identifies the committee.
	CommitteeQualifier string
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// ExpectedThreshold is the threshold that must be present onchain before this step runs.
	// Acts as a safety backstop: if the onchain change hasn't landed (e.g. due to a hook
	// misfire or manual replay), Apply returns an error rather than writing stale config.
	ExpectedThreshold uint8
	// ServiceIdentifier scopes the aggregator config DataStore output.
	ServiceIdentifier string
}

// DecreaseThresholdOffchain is step-2 of the DecreaseThreshold two-entry product (§5.6).
//
// It asserts that the onchain threshold has already been lowered to ExpectedThreshold,
// then regenerates the aggregator config to match. Triggered by the CLD post-proposal
// hook after timelock execution.
func DecreaseThresholdOffchain(registry *adapters.Registry) deployment.ChangeSetV2[DecreaseThresholdOffchainInput] {
	validate := func(e deployment.Environment, cfg DecreaseThresholdOffchainInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if cfg.ExpectedThreshold == 0 {
			return fmt.Errorf("expected threshold must be greater than zero")
		}
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
		}

		// Safety backstop: assert the onchain threshold already matches ExpectedThreshold
		// on every chain. Catches hook misfires and out-of-order manual invocations.
		ctx := context.Background()
		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return err
		}
		for sel, state := range committeeStates {
			for _, sc := range state.SignatureConfigs {
				if sc.Threshold != cfg.ExpectedThreshold {
					return fmt.Errorf(
						"chain %d source %d: onchain threshold %d does not match expected %d — step-1 may not have executed yet",
						sel, sc.SourceChainSelector, sc.Threshold, cfg.ExpectedThreshold,
					)
				}
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg DecreaseThresholdOffchainInput) (deployment.ChangesetOutput, error) {
		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors, &cfg.ExpectedThreshold)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to build aggregator config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge datastore: %w", err)
			}
		}
		if err := ccvdeployment.SaveAggregatorConfig(outputDS, cfg.ServiceIdentifier, committee); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to save aggregator config: %w", err)
		}

		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// validateThresholdDecrease returns an error if newThreshold is not strictly less than
// the current threshold on every chain.
func validateThresholdDecrease(
	states map[uint64]*adapters.CommitteeState,
	newThreshold uint8,
	qualifier string,
) error {
	for sel, state := range states {
		for _, sc := range state.SignatureConfigs {
			if newThreshold >= sc.Threshold {
				return fmt.Errorf(
					"chain %d source %d: new threshold %d is not less than current threshold %d",
					sel, sc.SourceChainSelector, newThreshold, sc.Threshold,
				)
			}
		}
	}
	return nil
}
