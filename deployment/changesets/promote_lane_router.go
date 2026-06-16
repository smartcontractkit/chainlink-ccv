package changesets

// PromoteLaneRouter changeset overview
//
// PromoteLaneRouter is a single-entry, onchain-only product that switches a
// lane from the TestRouter to the production Router (§5.2.2).
//
// Structurally it is a re-run of LaneExpansion with UseTestRouter=false. The
// distinction is semantic: PromoteLaneRouter assumes the lane already exists
// (was previously configured via LaneExpansion with UseTestRouter=true) and
// only swaps the Router reference on both sides.
//
// No offchain coupling — verifiers, executors, and indexers are unaffected by
// the Router swap.

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// PromoteLaneRouterInput is the imperative input for the PromoteLaneRouter changeset.
type PromoteLaneRouterInput struct {
	// SrcChainSelector is the source chain of the lane to promote.
	SrcChainSelector uint64
	// DestChainSelector is the destination chain of the lane to promote.
	DestChainSelector uint64
	// ExecutorQualifier identifies the executor to use on each chain for this
	// lane. Empty uses the adapter default. Should match the value used in
	// the original LaneExpansion.
	ExecutorQualifier string
	// InboundCCVQualifiers are committee verifier qualifiers for inbound traffic
	// verification. Should match the original LaneExpansion.
	InboundCCVQualifiers []string
	// OutboundCCVQualifiers are committee verifier qualifiers for outbound traffic
	// verification. Should match the original LaneExpansion.
	OutboundCCVQualifiers []string
	// SrcChainOverrides optionally overrides config for the source chain side.
	SrcChainOverrides *LaneChainOverrides
	// DestChainOverrides optionally overrides config for the destination chain side.
	DestChainOverrides *LaneChainOverrides
}

// PromoteLaneRouter is a single-entry, onchain-only changeset that switches a
// lane from the TestRouter to the production Router (§5.2.2).
//
// It re-configures the OnRamp and OffRamp on both sides of the lane to use the
// production Router address and wires them into the production Router via
// ApplyRampUpdates. The lane must have been previously configured via
// LaneExpansion.
//
// The changeset dispatches to the same LaneConfigAdapter as LaneExpansion,
// with UseTestRouter=false. The adapter's idempotency guarantees ensure that
// re-running is safe.
func PromoteLaneRouter() deployment.ChangeSetV2[PromoteLaneRouterInput] {
	validate := func(e deployment.Environment, cfg PromoteLaneRouterInput) error {
		return validateLaneInput(e, cfg.SrcChainSelector, cfg.DestChainSelector)
	}

	apply := func(e deployment.Environment, cfg PromoteLaneRouterInput) (deployment.ChangesetOutput, error) {
		return applyLaneConfig(e, cfg.SrcChainSelector, cfg.DestChainSelector,
			false, // UseTestRouter=false — production Router
			cfg.ExecutorQualifier,
			cfg.InboundCCVQualifiers, cfg.OutboundCCVQualifiers,
			cfg.SrcChainOverrides, cfg.DestChainOverrides)
	}

	return deployment.CreateChangeSet(apply, validate)
}
