package changesets

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// IncreaseThresholdInput is the input for the IncreaseThreshold changeset.
type IncreaseThresholdInput struct {
	// CommitteeQualifier identifies the committee whose threshold is being raised.
	CommitteeQualifier string
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// NewThreshold is the desired threshold. Must be greater than the current onchain threshold.
	NewThreshold uint8
	// ServiceIdentifier scopes the aggregator config DataStore output.
	ServiceIdentifier string
}

// IncreaseThreshold is an offchain-first single-pass changeset (§5.5).
//
// It regenerates the aggregator config with the new threshold before submitting the
// onchain change. This ordering is safe because a higher threshold in the offchain
// config is a strict superset of the pre-change onchain requirements — over-signed
// messages are harmless until the onchain change catches up.
//
// In deployer-key mode (the only mode supported until Phase 0) the onchain transaction
// is submitted directly inside Apply.
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
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
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

	apply := func(e deployment.Environment, cfg IncreaseThresholdInput) (deployment.ChangesetOutput, error) {
		ctx := context.Background()

		// Collect current committee state across all destination chains.
		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		// Validate that the new threshold is actually an increase and does not exceed
		// the signer count on any chain.
		if err := validateThresholdIncrease(committeeStates, cfg.NewThreshold, cfg.CommitteeQualifier); err != nil {
			return deployment.ChangesetOutput{}, err
		}

		// Step 1 (offchain-first): regenerate aggregator config with the new threshold.
		// This DataStore mutation lands at merge time, before the timelock fires.
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
		if err := ccvdeployment.SaveAggregatorConfig(outputDS, cfg.ServiceIdentifier, committee); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to save aggregator config: %w", err)
		}

		// Step 2 (onchain): submit applySignatureConfigs with the updated threshold.
		// In deployer-key mode this is a direct transaction submission.
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

		return deployment.ChangesetOutput{DataStore: outputDS}, nil
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
