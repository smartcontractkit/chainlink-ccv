package changesets

// UpdateSenderAllowlist changeset overview
//
// UpdateSenderAllowlist is a single-entry, onchain-only product (§5.12) that adds
// or removes individual sender addresses from a per-destination-chain allowlist on
// a CommitteeVerifier, or toggles the allowlist on/off for a destination chain.
//
// The allowlist is keyed by DestChainSelector — each destination chain has an
// independent allowlist (enabled flag + sender set). The update is applied on every
// chain in ChainSelectors where the committee verifier for CommitteeQualifier is
// deployed.
//
// No offchain coupling exists. With MCMS input the write is packaged into a
// timelock proposal; in deployer-key mode it is submitted directly.

import (
	"errors"
	"fmt"

	mcmsutil "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// UpdateSenderAllowlistInput is the imperative input for the UpdateSenderAllowlist
// changeset.
type UpdateSenderAllowlistInput struct {
	// CommitteeQualifier identifies the committee verifier to reconfigure.
	CommitteeQualifier string
	// ChainSelectors are the chains where the committee verifier is deployed and
	// whose allowlist should be updated.
	ChainSelectors []uint64
	// DestChainSelector is the destination chain whose independent allowlist is
	// being updated.
	DestChainSelector uint64
	// AllowlistEnabled toggles allowlist enforcement for DestChainSelector.
	AllowlistEnabled bool
	// AddedSenders are sender addresses (family-native string form) to add.
	AddedSenders []string
	// RemovedSenders are sender addresses to remove.
	RemovedSenders []string
	// MCMS, when set, packages the onchain writes into an MCMS timelock proposal
	// instead of submitting them with the deployer key.
	MCMS *mcmsutil.Input
}

// UpdateSenderAllowlist updates the per-destination-chain sender allowlist on the
// committee verifier across the specified chains (§5.12). Onchain-only, single-entry.
func UpdateSenderAllowlist() deployment.ChangeSetV2[UpdateSenderAllowlistInput] {
	validate := func(e deployment.Environment, cfg UpdateSenderAllowlistInput) error {
		if err := validateCommitteeOnchainTargets(e, cfg.CommitteeQualifier, cfg.ChainSelectors); err != nil {
			return err
		}
		if cfg.DestChainSelector == 0 {
			return errors.New("destination chain selector is required")
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg UpdateSenderAllowlistInput) (deployment.ChangesetOutput, error) {
		ctx := e.GetContext()
		writes := committeeWrites{mcms: cfg.MCMS}
		for _, sel := range cfg.ChainSelectors {
			onchain, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(sel)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: %w", sel, err)
			}
			ops, err := onchain.ApplyAllowlistUpdates(
				ctx, e, sel, cfg.CommitteeQualifier, cfg.DestChainSelector,
				cfg.AllowlistEnabled, cfg.AddedSenders, cfg.RemovedSenders,
			)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: ApplyAllowlistUpdates failed: %w", sel, err)
			}
			if err := writes.add(sel, ops); err != nil {
				return deployment.ChangesetOutput{}, err
			}
			e.Logger.Infow("Updated sender allowlist",
				"chain", sel,
				"committee", cfg.CommitteeQualifier,
				"destChain", cfg.DestChainSelector,
				"allowlistEnabled", cfg.AllowlistEnabled,
				"added", len(cfg.AddedSenders),
				"removed", len(cfg.RemovedSenders),
			)
		}
		return writes.output(e)
	}

	return deployment.CreateChangeSet(apply, validate)
}
