package inventory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// fakeCommitteeVerifierOnchain serves canned scans; the embedded nil adapter panics on anything else.
type fakeCommitteeVerifierOnchain struct {
	adapters.CommitteeVerifierOnchainAdapter
	states map[uint64][]*adapters.CommitteeState
}

func (f fakeCommitteeVerifierOnchain) ScanCommitteeStates(_ context.Context, _ deployment.Environment, chain uint64) ([]*adapters.CommitteeState, error) {
	return f.states[chain], nil
}

func TestAddOnchainCommittees(t *testing.T) {
	t.Parallel()

	// Like the real Canton adapter, report signers as addresses derived from the on-ledger keys.
	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyCanton, fakeCommitteeVerifierOnchain{
		states: map[uint64][]*adapters.CommitteeState{uint64(canton): {{
			Qualifier: "default", ChainSelector: uint64(canton), Address: "canton-verifier",
			SignatureConfigs: []adapters.SignatureConfig{{SourceChainSelector: uint64(ethereum), Threshold: 2, Signers: []string{alphaAddr, betaAddr}}},
		}}},
	})

	inv := Build(fixtureInputs())
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{})
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{}) // rerunning replaces, not duplicates

	onchain := committeeFor(t, inv, SourceOnchain, ethereum)
	assert.Equal(t, canton, onchain.VerifierChain)
	assert.Equal(t, "default", onchain.Qualifier)
	assert.Equal(t, Member{SignerAddress: alphaAddr, SignerPubKey: alphaKey, NOPAlias: "nop-alpha", NodeID: "node_alpha", CSAKey: "csa-alpha"},
		memberFor(t, onchain, alphaAddr))

	var onchainSets int
	for _, c := range inv.Committees {
		if c.Source == SourceOnchain {
			onchainSets++
		}
	}
	assert.Equal(t, 1, onchainSets)
	assert.Len(t, inv.ByChain()[canton].VerifierSignerSets, 1)

	assert.Contains(t, inv.Issues, Issue{
		Kind: IssueOnchainDrift, Subject: "canton-mainnet verifier, source ethereum-mainnet",
		Detail: "threshold 2 onchain, 2 in aggregator config; missing onchain: [" + gammaAddr + "]; only onchain: []",
	})
	assert.Contains(t, inv.Issues, Issue{
		Kind: IssueOnchainReadFailed, Subject: "ethereum-mainnet",
		Detail: `no adapter registered for chain family "evm" (selector 5009297550715157269)`,
	})
}
