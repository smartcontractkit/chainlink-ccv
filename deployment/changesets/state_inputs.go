package changesets

import (
	"context"
	"fmt"
	"slices"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// CommitteeInputFromState reconstructs the imperative CommitteeInput for a
// committee qualifier from observed state instead of a topology blob — the state
// analog of CommitteeInputFromTopologyPerFamily.
//
// Membership is read on-chain: for every chain the committee verifier is deployed
// on (discovered via adapters.AllDeployedCommitteeVerifierChains), the verifier's
// signature configs are scanned and their signer addresses mapped back to NOP
// aliases via ids. ChainConfigs is keyed by the verifier chain selector, matching
// how ApplyVerifierConfig consumes it (those keys drive verifier-contract
// resolution and signer-family detection).
//
// chainFamily filters to a single verifier-chain family per call, mirroring
// CommitteeInputFromTopologyPerFamily; pass "" to fold every family together.
//
// Aggregators are intentionally left empty: aggregator endpoints are offchain
// service infrastructure, not on/off-chain state, so the caller supplies them
// (see ApplyVerifierConfigInputFromState). The returned input is bootstrap-safe:
// when no verifier is deployed yet the result is an empty committee, not an error.
//
// Reconciliation note: on-chain, each verifier carries a *per-source* signer set,
// whereas CommitteeInput models a single membership per verifier chain. The two
// are reconciled by unioning the per-source signer sets into one membership. When
// the sources disagree (a member present on some sources but not others) the
// divergence is logged as a warning — it surfaces real drift while still producing
// a usable input; an unmappable signer (no JD-known NOP) remains a hard error.
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

	chainConfigs := make(map[uint64]CommitteeChainMembership)
	for _, sel := range verifierChains {
		family, err := chainsel.GetSelectorFamily(sel)
		if err != nil {
			return CommitteeInput{}, fmt.Errorf("committee %q: unknown family for chain %d: %w", qualifier, sel, err)
		}
		if chainFamily != "" && family != chainFamily {
			continue
		}

		onchain, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(sel)
		if err != nil {
			return CommitteeInput{}, fmt.Errorf("committee %q: %w", qualifier, err)
		}
		states, err := onchain.ScanCommitteeStates(ctx, env, sel)
		if err != nil {
			return CommitteeInput{}, fmt.Errorf("committee %q: scan chain %d: %w", qualifier, sel, err)
		}

		state, err := findCommitteeState(states, qualifier, sel)
		if err != nil {
			return CommitteeInput{}, err
		}
		if state == nil {
			// Committee not deployed on this chain (or scanned empty) — skip.
			continue
		}

		aliases, err := membershipFromState(ids, family, sel, qualifier, state, env.Logger)
		if err != nil {
			return CommitteeInput{}, err
		}
		if len(aliases) > 0 {
			chainConfigs[sel] = CommitteeChainMembership{NOPAliases: aliases}
		}
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

// membershipFromState collapses a verifier's per-source signer sets into the
// single NOP-alias membership CommitteeInput expects, mapping signer addresses to
// aliases via ids. Unknown signers (no JD-known NOP) are a hard error. When the
// per-source sets disagree the union is returned and the divergence is logged as a
// warning (drift the topology file could never surface), since collapsing to a
// single membership is inherently lossy.
func membershipFromState(
	ids *NOPIdentities,
	signerFamily string,
	verifierChain uint64,
	qualifier string,
	state *adapters.CommitteeState,
	lggr logger.Logger,
) ([]shared.NOPAlias, error) {
	union := make(map[shared.NOPAlias]struct{})
	perSource := make(map[uint64][]shared.NOPAlias, len(state.SignatureConfigs))
	var first map[shared.NOPAlias]struct{}
	diverged := false

	for _, sc := range state.SignatureConfigs {
		set := make(map[shared.NOPAlias]struct{}, len(sc.Signers))
		for _, signer := range sc.Signers {
			alias, ok := ids.AliasForSigner(signerFamily, signer)
			if !ok {
				return nil, fmt.Errorf(
					"committee %q on verifier chain %d (source %d): on-chain signer %q has no JD-known NOP — "+
						"signer set is out of sync with the Job Distributor",
					qualifier, verifierChain, sc.SourceChainSelector, signer)
			}
			set[alias] = struct{}{}
			union[alias] = struct{}{}
		}
		if first == nil {
			first = set
		} else if !aliasSetsEqual(first, set) {
			diverged = true
		}
		perSource[sc.SourceChainSelector] = sortedAliases(set)
	}

	if diverged && lggr != nil {
		lggr.Warnw(
			"committee membership differs across source chains on verifier; unioning into a single membership",
			"committee", qualifier,
			"verifierChain", verifierChain,
			"perSource", perSource,
		)
	}

	return sortedAliases(union), nil
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

func aliasSetsEqual(a, b map[shared.NOPAlias]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
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
	// Monitoring / PyroscopeURL are forwarded into the verifier job spec.
	Monitoring   ccvdeployment.MonitoringConfig
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
		Monitoring:               opts.Monitoring,
		TargetNOPs:               opts.TargetNOPs,
		DisableFinalityCheckers:  opts.DisableFinalityCheckers,
		RevokeOrphanedJobs:       opts.RevokeOrphanedJobs,
		ConsolidateAggregators:   opts.ConsolidateAggregators,
	}, nil
}
