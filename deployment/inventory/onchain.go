package inventory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// AddOnchainCommittees scans every chain a family adapter discovers CommitteeVerifier refs on,
// plus the chains aggregator configs point at and chains scanned before. Fresh rows replace a
// chain's snapshot only when its scan succeeds; a failed scan re-records the last successful
// snapshot. Drift and identity issues are rebuilt from the final rows, and each chain's refresh
// outcome is recorded so stale data is distinguishable from an actual removal.
func (inv *Inventory) AddOnchainCommittees(ctx context.Context, env deployment.Environment) {
	previous := onchainSnapshot(inv.Committees)
	inv.refreshFromScans(previous, inv.scanChains(env, previous), liveScan(ctx, env))
}

// RefreshChains rescans only the given chains, e.g. the chains a changeset already loaded.
// Every other chain's snapshot is kept without a new read attempt.
func (inv *Inventory) RefreshChains(ctx context.Context, env deployment.Environment, chains []uint64) {
	previous := onchainSnapshot(inv.Committees)
	slices.Sort(chains)
	inv.refreshFromScans(previous, slices.Compact(chains), liveScan(ctx, env))
}

// ApplyScannedCommitteeStates persists committee reads a changeset already made, replacing the
// scanned chains' snapshots without another RPC pass. states must be the raw reads, before any
// offchain threshold override. Unscanned chains keep their previous snapshots.
func (inv *Inventory) ApplyScannedCommitteeStates(chains []uint64, states []*adapters.CommitteeState) {
	previous := onchainSnapshot(inv.Committees)
	byChain := make(map[uint64][]*adapters.CommitteeState, len(chains))
	for _, state := range states {
		if state != nil {
			byChain[state.ChainSelector] = append(byChain[state.ChainSelector], state)
		}
	}
	slices.Sort(chains)
	inv.refreshFromScans(previous, slices.Compact(chains), func(chain uint64) ([]*adapters.CommitteeState, error) {
		return byChain[chain], nil
	})
}

func liveScan(ctx context.Context, env deployment.Environment) func(uint64) ([]*adapters.CommitteeState, error) {
	return func(chain uint64) ([]*adapters.CommitteeState, error) {
		adapter, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(chain)
		if err != nil {
			return nil, err
		}
		return adapter.ScanCommitteeStates(ctx, env, chain)
	}
}

// refreshFromScans rebuilds onchain rows and findings from scan results for the given chains.
// Successful scans replace their chain's snapshot; failed scans keep it and record the failure;
// chains outside the set keep their snapshot with no new refresh outcome.
func (inv *Inventory) refreshFromScans(previous map[uint64][]Committee, chains []uint64, scan func(uint64) ([]*adapters.CommitteeState, error)) {
	inv.clearOnchainState()
	b := builderFor(inv)
	r := buildResolver(inv.NOPs, inv.Nodes)
	recorded := aggregatorSets(inv.Committees)
	now := time.Now()
	scanned := make(map[uint64]bool, len(chains))
	for _, chain := range chains {
		scanned[chain] = true
		refresh := OnchainRefresh{Chain: ChainSelector(chain), LastAttemptAt: now}
		states, err := scan(chain)
		if err == nil {
			for _, state := range states {
				if state == nil {
					continue
				}
				for _, sc := range state.SignatureConfigs {
					c := Committee{
						Source:          SourceOnchain,
						VerifierChain:   ChainSelector(chain),
						VerifierAddress: state.Address,
						Qualifier:       state.Qualifier,
						SourceChain:     ChainSelector(sc.SourceChainSelector),
						Threshold:       sc.Threshold,
					}
					inv.recordOnchainCommittee(b, r, recorded, c, sc.Signers, sc.SignerPubKeys)
				}
			}
			refresh.LastSuccessAt = now
			inv.setRefresh(refresh)
			continue
		}
		refresh.LastError = err.Error()
		inv.setRefresh(refresh)
		inv.recordSnapshot(b, r, recorded, previous[chain])
	}
	for chain, rows := range previous {
		if !scanned[chain] {
			inv.recordSnapshot(b, r, recorded, rows)
		}
	}
	// Read-failure alerts track the final refresh records, so a chain outside this refresh
	// keeps its alert for as long as its last attempt failed, and only that.
	for _, refresh := range inv.Refreshes {
		if refresh.LastError != "" {
			b.issue(IssueOnchainReadFailed, chainLabel(uint64(refresh.Chain)), refresh.LastError)
		}
	}
	b.checkIdentities(r)
	inv.normalize()
}

// recordSnapshot re-records previously observed rows so drift and identity findings track the
// current aggregator configs and NOP tables even when the rows themselves are unchanged.
func (inv *Inventory) recordSnapshot(b *builder, r *resolver, recorded map[committeeKey][]Committee, rows []Committee) {
	for _, c := range rows {
		inv.recordOnchainCommittee(b, r, recorded, c, memberAddresses(c.Members), memberPubKeys(c.Members))
	}
}

// clearOnchainState drops onchain rows and every issue kind that is rebuilt from them, so a
// refresh never carries drift or identity findings calculated from an older snapshot.
func (inv *Inventory) clearOnchainState() {
	inv.Committees = slices.DeleteFunc(inv.Committees, func(c Committee) bool { return c.Source == SourceOnchain })
	inv.Issues = slices.DeleteFunc(inv.Issues, func(i Issue) bool {
		switch i.Kind {
		case IssueOnchainDrift, IssueOnchainReadFailed, IssueUnresolvedSigner,
			IssueMissingNode, IssueAmbiguousNode, IssueVerifierScopeConflict:
			return true
		}
		return false
	})
}

// onchainSnapshot groups the previously observed onchain rows by their verifier chain.
func onchainSnapshot(committees []Committee) map[uint64][]Committee {
	out := make(map[uint64][]Committee)
	for _, c := range committees {
		if c.Source == SourceOnchain {
			out[uint64(c.VerifierChain)] = append(out[uint64(c.VerifierChain)], c)
		}
	}
	return out
}

// scanChains lists the chains to scan: aggregator-configured destinations, chains where a family
// adapter discovers native refs, and chains scanned before. The last group covers removal: a
// chain whose refs are gone scans empty, so its old snapshot is cleared with a success status
// rather than lingering with no removal signal.
func (inv *Inventory) scanChains(env deployment.Environment, previous map[uint64][]Committee) []uint64 {
	chains := verifierChains(inv.Verifiers)
	for chain := range previous {
		chains = append(chains, chain)
	}
	for _, refresh := range inv.Refreshes {
		chains = append(chains, uint64(refresh.Chain))
	}
	adapters.GetCommitteeVerifierOnchainRegistry().ForEach(func(_ string, a adapters.CommitteeVerifierOnchainAdapter) {
		if d, ok := a.(adapters.CommitteeVerifierChainDiscovery); ok {
			chains = append(chains, d.DeployedCommitteeVerifierChains(env.DataStore)...)
		}
	})
	slices.Sort(chains)
	return slices.Compact(chains)
}

// setRefresh records the latest scan outcome for its chain, preserving the last success time
// across failed attempts so retained committees carry their actual data age.
func (inv *Inventory) setRefresh(refresh OnchainRefresh) {
	for i := range inv.Refreshes {
		if inv.Refreshes[i].Chain == refresh.Chain {
			if refresh.LastError != "" {
				refresh.LastSuccessAt = inv.Refreshes[i].LastSuccessAt
			}
			inv.Refreshes[i] = refresh
			return
		}
	}
	inv.Refreshes = append(inv.Refreshes, refresh)
}

// ReconcileOnchainCommittees restores a stored onchain snapshot and its refresh outcomes,
// resolving members against the current NOP and node tables and rebuilding drift and identity
// issues from the restored rows. Persisted read failures resurface as issues from Refreshes.
func (inv *Inventory) ReconcileOnchainCommittees(snapshot []Committee, refreshes []OnchainRefresh) {
	inv.clearOnchainState()
	inv.Refreshes = slices.Clone(refreshes)
	b := builderFor(inv)
	r := buildResolver(inv.NOPs, inv.Nodes)
	recorded := aggregatorSets(inv.Committees)
	for _, c := range snapshot {
		if c.Source != SourceOnchain {
			continue
		}
		inv.recordSnapshot(b, r, recorded, []Committee{c})
	}
	for _, refresh := range inv.Refreshes {
		if refresh.LastError != "" {
			b.issue(IssueOnchainReadFailed, chainLabel(uint64(refresh.Chain)), refresh.LastError)
		}
	}
	b.checkIdentities(r)
	inv.normalize()
}

// aggregatorSets indexes aggregator-recorded committees only: onchain rows are observations,
// never intent, so a previous snapshot cannot mask drift between the chain and the configs.
func aggregatorSets(committees []Committee) map[committeeKey][]Committee {
	recorded := make(map[committeeKey][]Committee)
	for _, c := range committees {
		if c.Source != SourceAggregator {
			continue
		}
		k := committeeKey{uint64(c.SourceChain), c.Qualifier}
		recorded[k] = append(recorded[k], c)
	}
	return recorded
}

func (inv *Inventory) recordOnchainCommittee(
	b *builder,
	r *resolver,
	recorded map[committeeKey][]Committee,
	c Committee,
	signers []string,
	pubKeys map[string]string,
) {
	c.Members = b.members(r, familyOf(uint64(c.VerifierChain)), signers, uint64(c.SourceChain), c.Qualifier, pubKeys)
	sets := recorded[committeeKey{uint64(c.SourceChain), c.Qualifier}]
	if len(sets) == 0 {
		// Aggregator configs saved before qualifiers were recorded match any committee.
		sets = recorded[committeeKey{uint64(c.SourceChain), ""}]
	}
	if drift := driftFrom(c, sets); drift != "" {
		b.issue(IssueOnchainDrift, fmt.Sprintf("%s verifier, source %s", chainLabel(uint64(c.VerifierChain)), chainLabel(uint64(c.SourceChain))), drift)
	}
	inv.Committees = append(inv.Committees, c)
}

// driftFrom describes how an onchain set differs from the aggregator sets for its source, or "".
func driftFrom(onchain Committee, recorded []Committee) string {
	if len(recorded) == 0 {
		return "no aggregator config has a signer set for this source"
	}
	for _, c := range recorded {
		if sameSignerSet(c, onchain) {
			return ""
		}
	}
	want, got := memberAddresses(recorded[0].Members), memberAddresses(onchain.Members)
	missing := slices.DeleteFunc(slices.Clone(want), func(a string) bool { return slices.Contains(got, a) })
	extra := slices.DeleteFunc(slices.Clone(got), func(a string) bool { return slices.Contains(want, a) })
	return fmt.Sprintf("threshold %d onchain, %d in aggregator config; missing onchain: [%s]; only onchain: [%s]",
		onchain.Threshold, recorded[0].Threshold, strings.Join(missing, ", "), strings.Join(extra, ", "))
}

func verifierChains(verifiers []Verifier) []uint64 {
	chains := make([]uint64, 0, len(verifiers))
	for _, v := range verifiers {
		chains = append(chains, uint64(v.Chain))
	}
	slices.Sort(chains)
	return slices.Compact(chains)
}
