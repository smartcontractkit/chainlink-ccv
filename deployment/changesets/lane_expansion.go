package changesets

// LaneExpansion changeset overview
//
// LaneExpansion is a single-entry, onchain-only product for wiring a new
// source→destination lane between two already-deployed chains (§5.2.1).
//
// The changeset configures both sides of the lane:
//  1. On the source chain: configures the OnRamp with destination chain config
//     and wires it into the selected Router (TestRouter or production).
//  2. On the destination chain: configures the OffRamp with source chain config
//     and wires it into the selected Router.
//
// No offchain coupling exists — verifiers, executors, and indexers discover
// lanes by polling onchain state.
//
// In MCMS mode the changeset returns BatchOps for both chains. In deployer-key
// mode transactions are submitted directly.

import (
	"errors"
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// LaneChainOverrides carries optional per-chain overrides for a lane.
// Nil pointer fields fall back to adapter defaults.
type LaneChainOverrides struct {
	// AllowTrafficFrom enables/disables inbound traffic. Nil uses adapter default.
	AllowTrafficFrom *bool
	// BaseExecutionGasCost overrides the default base execution gas cost.
	BaseExecutionGasCost *uint32
	// TokenReceiverAllowed overrides whether token receivers are allowed.
	TokenReceiverAllowed *bool
	// MessageNetworkFeeUSDCents overrides the message network fee.
	MessageNetworkFeeUSDCents *uint16
	// TokenNetworkFeeUSDCents overrides the token network fee.
	TokenNetworkFeeUSDCents *uint16
	// FamilyExtras carries chain-family-specific overrides (e.g. FeeQuoter dest
	// chain config, executor dest chain config) that the adapter interprets.
	FamilyExtras map[string]any
}

// LaneExpansionInput is the imperative input for the LaneExpansion changeset.
type LaneExpansionInput struct {
	// SrcChainSelector is the source chain of the lane.
	SrcChainSelector uint64
	// DestChainSelector is the destination chain of the lane.
	DestChainSelector uint64
	// UseTestRouter selects the TestRouter instead of the production Router.
	// Set to true for initial integration testing; use PromoteLaneRouter to
	// switch to the production Router later.
	UseTestRouter bool
	// ExecutorQualifier identifies the executor to use on each chain for this
	// lane. Empty uses the adapter default.
	ExecutorQualifier string
	// InboundCCVQualifiers are committee verifier qualifiers for inbound traffic
	// verification on each side of the lane.
	InboundCCVQualifiers []string
	// OutboundCCVQualifiers are committee verifier qualifiers for outbound traffic
	// verification on each side of the lane.
	OutboundCCVQualifiers []string
	// SrcChainOverrides optionally overrides config for the source chain side.
	SrcChainOverrides *LaneChainOverrides
	// DestChainOverrides optionally overrides config for the destination chain side.
	DestChainOverrides *LaneChainOverrides
}

// LaneExpansion is a single-entry, onchain-only changeset that wires a new
// source→destination lane between two already-deployed chains (§5.2.1).
//
// Both sides of the lane are configured: the source chain's OnRamp and the
// destination chain's OffRamp, each wired into the selected Router
// (TestRouter when UseTestRouter is true, production Router otherwise).
//
// The changeset dispatches to the per-chain LaneConfigAdapter registered for
// each chain's family. The adapter handles address resolution (OnRamp,
// OffRamp, Router, FeeQuoter) from the DataStore and executes the onchain
// configuration calls.
func LaneExpansion() deployment.ChangeSetV2[LaneExpansionInput] {
	validate := func(e deployment.Environment, cfg LaneExpansionInput) error {
		return validateLaneInput(e, cfg.SrcChainSelector, cfg.DestChainSelector)
	}

	apply := func(e deployment.Environment, cfg LaneExpansionInput) (deployment.ChangesetOutput, error) {
		return applyLaneConfig(e, cfg.SrcChainSelector, cfg.DestChainSelector,
			cfg.UseTestRouter, cfg.ExecutorQualifier,
			cfg.InboundCCVQualifiers, cfg.OutboundCCVQualifiers,
			cfg.SrcChainOverrides, cfg.DestChainOverrides)
	}

	return deployment.CreateChangeSet(apply, validate)
}

// validateLaneInput validates the common preconditions for lane expansion and
// router promotion.
func validateLaneInput(
	e deployment.Environment,
	srcChainSelector, destChainSelector uint64,
) error {
	if srcChainSelector == 0 {
		return errors.New("source chain selector is required")
	}
	if destChainSelector == 0 {
		return errors.New("destination chain selector is required")
	}
	if srcChainSelector == destChainSelector {
		return errors.New("source and destination chain selectors must be different")
	}

	envSelectors := e.BlockChains.ListChainSelectors()
	if !slices.Contains(envSelectors, srcChainSelector) {
		return fmt.Errorf("source chain selector %d is not available in environment", srcChainSelector)
	}
	if !slices.Contains(envSelectors, destChainSelector) {
		return fmt.Errorf("destination chain selector %d is not available in environment", destChainSelector)
	}

	for _, sel := range []uint64{srcChainSelector, destChainSelector} {
		if _, err := adapters.GetLaneConfigRegistry().Get(sel); err != nil {
			return fmt.Errorf("chain %d: %w", sel, err)
		}
	}

	return nil
}

// applyLaneConfig configures both sides of a lane. It dispatches to the
// LaneConfigAdapter on each chain.
func applyLaneConfig(
	e deployment.Environment,
	srcChainSelector, destChainSelector uint64,
	useTestRouter bool,
	executorQualifier string,
	inboundCCVQualifiers, outboundCCVQualifiers []string,
	srcOverrides, destOverrides *LaneChainOverrides,
) (deployment.ChangesetOutput, error) {
	outputDS := datastore.NewMemoryDataStore()
	var allReports []operations.Report[any, any]

	// Configure both sides: src chain with dest as remote, dest chain with src as remote.
	sides := []struct {
		localSel  uint64
		remoteSel uint64
		overrides *LaneChainOverrides
	}{
		{localSel: srcChainSelector, remoteSel: destChainSelector, overrides: srcOverrides},
		{localSel: destChainSelector, remoteSel: srcChainSelector, overrides: destOverrides},
	}

	for _, side := range sides {
		remoteLaneCfg := buildRemoteLaneConfig(
			executorQualifier, inboundCCVQualifiers, outboundCCVQualifiers, side.overrides,
		)

		existingAddresses := e.DataStore.Addresses().Filter(
			datastore.AddressRefByChainSelector(side.localSel),
		)

		input := adapters.LaneConfigInput{
			ChainSelector:     side.localSel,
			UseTestRouter:     useTestRouter,
			ExistingAddresses: existingAddresses,
			RemoteChains: map[uint64]adapters.RemoteLaneConfig{
				side.remoteSel: remoteLaneCfg,
			},
		}

		laneAdapter, err := adapters.GetLaneConfigRegistry().Get(side.localSel)
		if err != nil {
			return deployment.ChangesetOutput{Reports: allReports, DataStore: outputDS},
				fmt.Errorf("chain %d: %w", side.localSel, err)
		}

		report, err := operations.ExecuteSequence(
			e.OperationsBundle,
			laneAdapter.ConfigureLane(),
			e.BlockChains,
			input,
		)
		allReports = append(allReports, report.ExecutionReports...)
		if err != nil {
			return deployment.ChangesetOutput{Reports: allReports, DataStore: outputDS},
				fmt.Errorf("chain %d: ConfigureLane failed: %w", side.localSel, err)
		}

		for _, ref := range report.Output.Addresses {
			if addErr := outputDS.Addresses().Add(ref); addErr != nil &&
				!errors.Is(addErr, datastore.ErrAddressRefExists) {
				return deployment.ChangesetOutput{Reports: allReports, DataStore: outputDS},
					fmt.Errorf("chain %d: failed to add address %s to datastore: %w",
						side.localSel, ref.Address, addErr)
			}
		}

		e.Logger.Infow("Lane configured",
			"localChain", side.localSel,
			"remoteChain", side.remoteSel,
			"useTestRouter", useTestRouter,
		)
	}

	return deployment.ChangesetOutput{
		Reports:   allReports,
		DataStore: outputDS,
	}, nil
}

// buildRemoteLaneConfig assembles a RemoteLaneConfig from the changeset input.
func buildRemoteLaneConfig(
	executorQualifier string,
	inboundCCVQualifiers, outboundCCVQualifiers []string,
	overrides *LaneChainOverrides,
) adapters.RemoteLaneConfig {
	cfg := adapters.RemoteLaneConfig{
		ExecutorQualifier:     executorQualifier,
		InboundCCVQualifiers:  inboundCCVQualifiers,
		OutboundCCVQualifiers: outboundCCVQualifiers,
	}
	if overrides != nil {
		cfg.AllowTrafficFrom = overrides.AllowTrafficFrom
		cfg.BaseExecutionGasCost = overrides.BaseExecutionGasCost
		cfg.TokenReceiverAllowed = overrides.TokenReceiverAllowed
		cfg.MessageNetworkFeeUSDCents = overrides.MessageNetworkFeeUSDCents
		cfg.TokenNetworkFeeUSDCents = overrides.TokenNetworkFeeUSDCents
		cfg.FamilyExtras = overrides.FamilyExtras
	}
	return cfg
}
