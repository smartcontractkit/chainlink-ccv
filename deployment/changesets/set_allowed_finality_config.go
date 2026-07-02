package changesets

// SetAllowedFinalityConfig changeset overview
//
// SetAllowedFinalityConfig is a single-entry, onchain-only product (§5.11) that
// updates the allowed-finality config on a CommitteeVerifier contract — e.g.
// tightening finality after a reorg, or relaxing it for a low-value lane.
//
// The finality config is the verifier's single allowed-finality tag (not per
// remote chain). It is applied on every chain in ChainSelectors where the
// committee verifier for CommitteeQualifier is deployed.
//
// No offchain coupling exists: the change takes effect onchain and services read
// it at the next attestation cycle. In deployer-key mode the transaction is
// submitted directly; MCMS-mode support is deferred to Phase 0 (CLD
// post-proposal hook prerequisite), matching the other committee onchain
// products (AddNOPToCommittee, Increase/DecreaseThreshold).

import (
	"errors"
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// SetAllowedFinalityConfigInput is the imperative input for the
// SetAllowedFinalityConfig changeset.
type SetAllowedFinalityConfigInput struct {
	// CommitteeQualifier identifies the committee verifier to reconfigure.
	CommitteeQualifier string
	// ChainSelectors are the chains where the committee verifier is deployed and
	// whose allowed-finality config should be set.
	ChainSelectors []uint64
	// The three fields below describe the *allowed* finality, which the adapter
	// encodes as an OR combination — a verifier may accept more than one finality
	// level at once. At least one of them must be set (enforced in validation).
	//
	// WaitForFinality allows full finality. It is the zero-value/default tag
	// (encoded as all-zero on chain), so it is implicit whenever no other field
	// is set; set it explicitly to allow full finality alongside WaitForSafe
	// and/or BlockDepth.
	WaitForFinality bool
	// WaitForSafe allows the "safe" finality level.
	WaitForSafe bool
	// BlockDepth allows waiting up to the given number of block confirmations.
	BlockDepth uint16
}

// SetAllowedFinalityConfig updates the allowed-finality config on the committee
// verifier across the specified chains (§5.11). Onchain-only, single-entry.
func SetAllowedFinalityConfig() deployment.ChangeSetV2[SetAllowedFinalityConfigInput] {
	validate := func(e deployment.Environment, cfg SetAllowedFinalityConfigInput) error {
		if err := validateCommitteeOnchainTargets(e, cfg.CommitteeQualifier, cfg.ChainSelectors); err != nil {
			return err
		}
		// Reject an empty config: with no mode set the input encodes to all-zero,
		// which silently means "wait for finality" — almost always an unintended
		// no-op rather than a deliberate choice. Mirrors finality.Config.Validate.
		if !cfg.WaitForFinality && !cfg.WaitForSafe && cfg.BlockDepth == 0 {
			return errors.New("at least one finality mode must be set (waitForFinality, waitForSafe, or blockDepth)")
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg SetAllowedFinalityConfigInput) (deployment.ChangesetOutput, error) {
		ctx := e.GetContext()
		for _, sel := range cfg.ChainSelectors {
			onchain, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(sel)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: %w", sel, err)
			}
			if err := onchain.SetAllowedFinalityConfig(
				ctx, e, sel, cfg.CommitteeQualifier,
				cfg.WaitForFinality, cfg.WaitForSafe, cfg.BlockDepth,
			); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: SetAllowedFinalityConfig failed: %w", sel, err)
			}
			e.Logger.Infow("Set allowed finality config",
				"chain", sel,
				"committee", cfg.CommitteeQualifier,
				"waitForFinality", cfg.WaitForFinality,
				"waitForSafe", cfg.WaitForSafe,
				"blockDepth", cfg.BlockDepth,
			)
		}
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// validateCommitteeOnchainTargets is the shared precondition check for the
// committee-verifier onchain-only products (SetAllowedFinalityConfig,
// UpdateSenderAllowlist): a qualifier is required, at least one unique chain
// selector that is present in the environment, and a registered committee
// verifier onchain adapter for each chain's family.
func validateCommitteeOnchainTargets(e deployment.Environment, qualifier string, chainSelectors []uint64) error {
	if qualifier == "" {
		return errors.New("committee qualifier is required")
	}
	if len(chainSelectors) == 0 {
		return errors.New("at least one chain selector is required")
	}
	envSelectors := e.BlockChains.ListChainSelectors()
	seen := make(map[uint64]bool, len(chainSelectors))
	for _, sel := range chainSelectors {
		if seen[sel] {
			return fmt.Errorf("duplicate chain selector %d", sel)
		}
		seen[sel] = true
		if !slices.Contains(envSelectors, sel) {
			return fmt.Errorf("chain selector %d is not available in environment", sel)
		}
		if _, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(sel); err != nil {
			return fmt.Errorf("chain %d: %w", sel, err)
		}
	}
	return nil
}
