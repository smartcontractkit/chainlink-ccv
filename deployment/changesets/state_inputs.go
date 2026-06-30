package changesets

import (
	"context"
	"fmt"
	"slices"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// CommitteeInputFromState reconstructs the imperative CommitteeInput for a
// committee qualifier from observed state instead of a topology blob — the state
// analog of CommitteeInputFromTopologyPerFamily.
//
// Membership is read on-chain. A committee verifier deployed on chain V stores a
// *per-source* signer set: its config for source chain S carries the signers of the
// committee members responsible for S (see getSignatureConfigForLane in
// chainlink-ccip, which derives those signers from the topology's ChainConfigs[S]).
// The signers physically stored on V therefore belong to V's *counterparties*, not
// to V itself. Reconstruction keys membership by *source* chain accordingly: every
// deployed verifier chain is scanned (discovered via
// adapters.AllDeployedCommitteeVerifierChains), and each signature config's signers
// are attributed to its SourceChainSelector, resolved to NOP aliases via ids using
// the verifier chain's address family. The result is keyed identically to
// CommitteeInputFromTopologyPerFamily (by the chain a membership belongs to), so the
// two compare directly.
//
// Keying by source rather than by verifier chain is essential for committees whose
// membership differs per chain — e.g. one committee spanning multiple chain families,
// where chain V's verifier holds only its counterparties' signers. A by-verifier-chain
// key would mislabel those as V's own members and report a spurious mismatch.
//
// chainFamily filters the *result* to source chains of a single family; pass "" to
// include every chain. Scanning always covers all verifier-chain families, since a
// source chain's signers live on its counterparties' verifiers.
//
// Aggregators are intentionally left empty: aggregator endpoints are offchain
// service infrastructure, not on/off-chain state, so the caller supplies them
// (see ApplyVerifierConfigInputFromState). The returned input is bootstrap-safe:
// when no verifier is deployed yet the result is an empty committee, not an error.
// An unmappable signer (no JD-known NOP) remains a hard error.
func CommitteeInputFromState(
	ctx context.Context,
	env deployment.Environment,
	ids *NOPIdentities,
	qualifier string,
	chainFamily string,
) (CommitteeInput, error) {
	if ids == nil {
		return CommitteeInput{}, fmt.Errorf("nil NOPIdentities: call LoadNOPIdentities first")
	}

	verifierChains := adapters.AllDeployedCommitteeVerifierChains(env.DataStore, qualifier)
	slices.Sort(verifierChains)

	// sourceChain -> member aliases, unioned across every verifier that attests it.
	// A source chain's signers live on its counterparties' verifiers, so we scan all
	// verifier-chain families regardless of the requested chainFamily; with >2 chains
	// a source's signer set appears on each counterparty verifier, all describing the
	// same committee, so unioning is idempotent.
	bySource := make(map[uint64]map[shared.NOPAlias]struct{})
	for _, vSel := range verifierChains {
		vFamily, err := chainsel.GetSelectorFamily(vSel)
		if err != nil {
			return CommitteeInput{}, fmt.Errorf("committee %q: unknown family for verifier chain %d: %w", qualifier, vSel, err)
		}

		onchain, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(vSel)
		if err != nil {
			return CommitteeInput{}, fmt.Errorf("committee %q: %w", qualifier, err)
		}
		states, err := onchain.ScanCommitteeStates(ctx, env, vSel)
		if err != nil {
			return CommitteeInput{}, fmt.Errorf("committee %q: scan chain %d: %w", qualifier, vSel, err)
		}

		state, err := findCommitteeState(states, qualifier, vSel)
		if err != nil {
			return CommitteeInput{}, err
		}
		if state == nil {
			// Committee not deployed on this chain (or scanned empty) — skip.
			continue
		}

		// Attribute each signature config's signers to the source chain it attests.
		// Signers are stored in the verifier chain's address family, so resolve with vFamily.
		for _, sc := range state.SignatureConfigs {
			set := bySource[sc.SourceChainSelector]
			if set == nil {
				set = make(map[shared.NOPAlias]struct{}, len(sc.Signers))
				bySource[sc.SourceChainSelector] = set
			}
			for _, signer := range sc.Signers {
				alias, ok := ids.AliasForSigner(vFamily, signer)
				if !ok {
					return CommitteeInput{}, fmt.Errorf(
						"committee %q: on-chain signer %q (verifier chain %d, source %d) has no JD-known NOP — "+
							"signer set is out of sync with the Job Distributor",
						qualifier, signer, vSel, sc.SourceChainSelector)
				}
				set[alias] = struct{}{}
			}
		}
	}

	chainConfigs := make(map[uint64]CommitteeChainMembership, len(bySource))
	for sSel, set := range bySource {
		if len(set) == 0 {
			continue
		}
		if chainFamily != "" {
			sFamily, err := chainsel.GetSelectorFamily(sSel)
			if err != nil {
				return CommitteeInput{}, fmt.Errorf("committee %q: unknown family for source chain %d: %w", qualifier, sSel, err)
			}
			if sFamily != chainFamily {
				continue
			}
		}
		chainConfigs[sSel] = CommitteeChainMembership{NOPAliases: sortedAliases(set)}
	}

	return CommitteeInput{Qualifier: qualifier, ChainConfigs: chainConfigs}, nil
}

// findCommitteeState returns the scanned state matching the qualifier on the given
// chain, or nil when none match. More than one match is an error: duplicate
// verifier states for a qualifier on one chain cannot be disambiguated and would
// hide drift (mirrors how GenerateAggregatorConfig treats duplicates).
func findCommitteeState(states []*adapters.CommitteeState, qualifier string, chainSelector uint64) (*adapters.CommitteeState, error) {
	var found *adapters.CommitteeState
	for _, s := range states {
		if s != nil && s.Qualifier == qualifier {
			if found != nil {
				return nil, fmt.Errorf(
					"committee %q: multiple committee verifier states found on chain %d; cannot disambiguate membership",
					qualifier, chainSelector)
			}
			found = s
		}
	}
	return found, nil
}

// CommitteeChainSelectorsFromState returns the sorted verifier-chain selectors a
// committee is deployed on, optionally filtered to a single family. Mirror of
// CommitteeChainSelectorsFromTopology, sourced from the datastore.
func CommitteeChainSelectorsFromState(ds datastore.DataStore, qualifier, chainFamily string) ([]uint64, error) {
	chains := adapters.AllDeployedCommitteeVerifierChains(ds, qualifier)
	out := make([]uint64, 0, len(chains))
	for _, sel := range chains {
		if chainFamily != "" {
			family, err := chainsel.GetSelectorFamily(sel)
			if err != nil {
				return nil, fmt.Errorf("committee %q: unknown family for chain %d: %w", qualifier, sel, err)
			}
			if family != chainFamily {
				continue
			}
		}
		out = append(out, sel)
	}
	slices.Sort(out)
	return out, nil
}

func sortedAliases(set map[shared.NOPAlias]struct{}) []shared.NOPAlias {
	out := make([]shared.NOPAlias, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

// VerifierConfigFromStateOptions carries the inputs that are NOT recoverable from
// on/off-chain state and must be supplied by the operator: aggregator service
// endpoints, the executor qualifier, monitoring/profiling settings, NOP mode
// overrides, and the usual publish-time flags.
type VerifierConfigFromStateOptions struct {
	// Aggregators are the committee's aggregator service endpoints. Offchain
	// infrastructure — not derivable from state — so they must be supplied.
	Aggregators []AggregatorRef
	// DefaultExecutorQualifier resolves the executor proxy baked into job specs.
	DefaultExecutorQualifier string
	// PyroscopeURL is forwarded into the verifier job spec. Monitoring is intentionally not here:
	// it is operator-provided via the bootstrap config, not the JD-shipped app config.
	PyroscopeURL string
	// ModeByNOP overrides the per-NOP mode (defaults to CL when absent).
	ModeByNOP map[shared.NOPAlias]shared.NOPMode
	// Publish-time flags, passed through verbatim.
	TargetNOPs              []shared.NOPAlias
	DisableFinalityCheckers []string
	RevokeOrphanedJobs      bool
	ConsolidateAggregators  bool
}

// ApplyVerifierConfigInputFromState assembles a ready-to-apply
// ApplyVerifierConfigInput by reconstructing the committee membership and NOP set
// from state, then merging the operator-supplied options. This is the end-to-end
// entry point: feed the result straight into ApplyVerifierConfig().Apply.
//
// The NOP set is restricted to the committee's membership (the union across its
// verifier chains) so callers don't carry every org NOP into every publish; when
// the committee is empty (bootstrap) every JD-known NOP is included.
func ApplyVerifierConfigInputFromState(
	ctx context.Context,
	env deployment.Environment,
	qualifier string,
	chainFamily string,
	opts VerifierConfigFromStateOptions,
) (ApplyVerifierConfigInput, error) {
	ids, err := LoadNOPIdentities(ctx, env)
	if err != nil {
		return ApplyVerifierConfigInput{}, err
	}

	committee, err := CommitteeInputFromState(ctx, env, ids, qualifier, chainFamily)
	if err != nil {
		return ApplyVerifierConfigInput{}, err
	}
	committee.Aggregators = opts.Aggregators

	nops := ids.NOPInputs()
	if opts.ModeByNOP != nil {
		for i := range nops {
			if mode, ok := opts.ModeByNOP[nops[i].Alias]; ok {
				nops[i].Mode = mode
			}
		}
	}
	// Restrict to committee membership (union across chains); empty committee
	// falls back to all NOPs, matching committeeNOPAliasesFromInput's contract.
	members := committeeNOPAliasesFromInput(committee, nops)
	nops = filterNOPInputsByAliases(nops, members)

	return ApplyVerifierConfigInput{
		CommitteeQualifier:       qualifier,
		DefaultExecutorQualifier: opts.DefaultExecutorQualifier,
		NOPs:                     nops,
		Committee:                committee,
		PyroscopeURL:             opts.PyroscopeURL,
		TargetNOPs:               opts.TargetNOPs,
		DisableFinalityCheckers:  opts.DisableFinalityCheckers,
		RevokeOrphanedJobs:       opts.RevokeOrphanedJobs,
		ConsolidateAggregators:   opts.ConsolidateAggregators,
	}, nil
}
