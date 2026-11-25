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
// plus the chains aggregator configs point at, through the CommitteeVerifierOnchainAdapter its
// family registers. Each chain's rows are replaced only when its scan succeeds; a failed scan
// keeps the last successful snapshot and records the failure in Refreshes and the issues.
func (inv *Inventory) AddOnchainCommittees(ctx context.Context, env deployment.Environment) {
	b := builderFor(inv)
	r := buildResolver(inv.NOPs, inv.Nodes)
	recorded := aggregatorSets(inv.Committees)
	now := time.Now()

	for _, chain := range scanChains(inv, env) {
		refresh := OnchainRefresh{Chain: ChainSelector(chain), LastAttemptAt: now}
		adapter, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(chain)
		if err != nil {
			refresh.LastError = err.Error()
			b.issue(IssueOnchainReadFailed, chainLabel(chain), err.Error())
			inv.setRefresh(refresh)
			continue
		}
		states, err := adapter.ScanCommitteeStates(ctx, env, chain)
		if err != nil {
			refresh.LastError = err.Error()
			b.issue(IssueOnchainReadFailed, chainLabel(chain), err.Error())
			inv.setRefresh(refresh)
			continue
		}
		inv.Committees = slices.DeleteFunc(inv.Committees, func(c Committee) bool {
			return c.Source == SourceOnchain && c.VerifierChain == ChainSelector(chain)
		})
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
	}
	b.reportIdentityGaps()
	inv.normalize()
}

// scanChains lists the chains to scan: aggregator-configured destinations plus every chain where
// a registered family adapter discovers native CommitteeVerifier refs, so a deployed verifier is
// scanned even when no aggregator config lists it.
func scanChains(inv *Inventory, env deployment.Environment) []uint64 {
	chains := verifierChains(inv.Verifiers)
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

// ReconcileOnchainCommittees restores a stored onchain snapshot and its refresh outcomes, and
// resolves the snapshot's members against the current NOP and node tables.
func (inv *Inventory) ReconcileOnchainCommittees(snapshot []Committee, refreshes []OnchainRefresh) {
	inv.Committees = slices.DeleteFunc(inv.Committees, func(c Committee) bool { return c.Source == SourceOnchain })
	inv.Refreshes = slices.Clone(refreshes)
	b := builderFor(inv)
	r := buildResolver(inv.NOPs, inv.Nodes)
	recorded := aggregatorSets(inv.Committees)
	for _, c := range snapshot {
		if c.Source != SourceOnchain {
			continue
		}
		inv.recordOnchainCommittee(b, r, recorded, c, memberAddresses(c.Members), memberPubKeys(c.Members))
	}
	b.reportIdentityGaps()
	inv.normalize()
}

func aggregatorSets(committees []Committee) map[committeeKey][]Committee {
	recorded := make(map[committeeKey][]Committee)
	for _, c := range committees {
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
