package inventory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// AddOnchainCommittees reads each destination verifier through the CommitteeVerifierOnchainAdapter
// its family registers, adding one onchain committee per source chain it holds. Chains it cannot
// read and sets that differ from the aggregator configs are recorded as issues.
func (inv *Inventory) AddOnchainCommittees(ctx context.Context, env deployment.Environment) {
	inv.Committees = slices.DeleteFunc(inv.Committees, func(c Committee) bool { return c.Source == SourceOnchain })
	b := builderFor(inv)
	r := buildResolver(inv.NOPs, inv.Nodes)
	recorded := aggregatorSets(inv.Committees)

	for _, chain := range verifierChains(inv.Verifiers) {
		adapter, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(chain)
		if err != nil {
			b.issue(IssueOnchainReadFailed, chainLabel(chain), err.Error())
			continue
		}
		states, err := adapter.ScanCommitteeStates(ctx, env, chain)
		if err != nil {
			b.issue(IssueOnchainReadFailed, chainLabel(chain), err.Error())
			continue
		}
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
				inv.recordOnchainCommittee(b, r, recorded, c, sc.Signers)
			}
		}
	}
	b.reportIdentityGaps()
	inv.normalize()
}

// ReconcileOnchainCommittees restores a stored onchain snapshot and resolves its members against
// the current NOP and node tables.
func (inv *Inventory) ReconcileOnchainCommittees(snapshot []Committee) {
	inv.Committees = slices.DeleteFunc(inv.Committees, func(c Committee) bool { return c.Source == SourceOnchain })
	b := builderFor(inv)
	r := buildResolver(inv.NOPs, inv.Nodes)
	recorded := aggregatorSets(inv.Committees)
	for _, c := range snapshot {
		if c.Source != SourceOnchain {
			continue
		}
		inv.recordOnchainCommittee(b, r, recorded, c, memberAddresses(c.Members))
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
) {
	c.Members = b.members(r, familyOf(uint64(c.VerifierChain)), signers, uint64(c.SourceChain))
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
