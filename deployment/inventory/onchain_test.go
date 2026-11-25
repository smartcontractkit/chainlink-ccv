package inventory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// fakeCommitteeVerifierOnchain serves canned scans; the embedded nil adapter panics on anything else.
// Tests that register it must not run in parallel: the adapter registry is process-global.
type fakeCommitteeVerifierOnchain struct {
	adapters.CommitteeVerifierOnchainAdapter
	states     map[uint64][]*adapters.CommitteeState
	errs       map[uint64]error
	discovered []uint64
}

func (f *fakeCommitteeVerifierOnchain) ScanCommitteeStates(_ context.Context, _ deployment.Environment, chain uint64) ([]*adapters.CommitteeState, error) {
	if f.errs[chain] != nil {
		return nil, f.errs[chain]
	}
	return f.states[chain], nil
}

func (f *fakeCommitteeVerifierOnchain) DeployedCommitteeVerifierChains(_ datastore.DataStore) []uint64 {
	return f.discovered
}

func TestAddOnchainCommittees(t *testing.T) {
	t.Parallel()

	// Like the real Canton adapter, report signers as addresses derived from the on-ledger keys.
	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyCanton, &fakeCommitteeVerifierOnchain{
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

func TestAddOnchainCommitteesFailedScanKeepsSnapshot(t *testing.T) {
	adapter := &fakeCommitteeVerifierOnchain{
		states: map[uint64][]*adapters.CommitteeState{uint64(canton): {{
			Qualifier: "default", ChainSelector: uint64(canton), Address: "canton-verifier",
			SignatureConfigs: []adapters.SignatureConfig{{SourceChainSelector: uint64(ethereum), Threshold: 2, Signers: []string{alphaAddr, betaAddr}}},
		}}},
	}
	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyCanton, adapter)

	inv := Build(fixtureInputs())
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{})
	first := refreshFor(t, inv, canton)
	require.False(t, first.LastSuccessAt.IsZero())
	require.Empty(t, first.LastError)

	adapter.errs = map[uint64]error{uint64(canton): errors.New("ledger unavailable")}
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{})

	onchain := committeeFor(t, inv, SourceOnchain, ethereum)
	assert.Equal(t, canton, onchain.VerifierChain, "a failed scan retains the last successful snapshot")
	assert.Equal(t, Member{SignerAddress: alphaAddr, SignerPubKey: alphaKey, NOPAlias: "nop-alpha", NodeID: "node_alpha", CSAKey: "csa-alpha"},
		memberFor(t, onchain, alphaAddr))
	stale := refreshFor(t, inv, canton)
	assert.Equal(t, first.LastSuccessAt, stale.LastSuccessAt, "the retained data keeps its original success time")
	assert.Equal(t, "ledger unavailable", stale.LastError)
	assert.False(t, stale.LastAttemptAt.Before(first.LastAttemptAt))
	assert.Contains(t, inv.Issues, Issue{Kind: IssueOnchainReadFailed, Subject: "canton-mainnet", Detail: "ledger unavailable"})

	adapter.errs = nil
	adapter.states = map[uint64][]*adapters.CommitteeState{uint64(canton): nil}
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{})

	for _, c := range inv.Committees {
		assert.NotEqual(t, SourceOnchain, c.Source, "a successful empty scan records an actual removal")
	}
	removed := refreshFor(t, inv, canton)
	assert.Empty(t, removed.LastError)
	assert.True(t, removed.LastSuccessAt.After(first.LastSuccessAt) || removed.LastSuccessAt.Equal(first.LastSuccessAt))
	assert.NotContains(t, inv.Issues, Issue{Kind: IssueOnchainReadFailed, Subject: "canton-mainnet", Detail: "ledger unavailable"},
		"a recovered chain loses its stale read-failure alert")
}

func TestAddOnchainCommitteesRebuildsDriftFromFinalRows(t *testing.T) {
	adapter := &fakeCommitteeVerifierOnchain{}
	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyCanton, adapter)
	drift := Issue{
		Kind: IssueOnchainDrift, Subject: "canton-mainnet verifier, source ethereum-mainnet",
		Detail: "threshold 2 onchain, 2 in aggregator config; missing onchain: [" + gammaAddr + "]; only onchain: []",
	}
	inv := Build(fixtureInputs())
	scan := func(signers ...string) {
		adapter.states = map[uint64][]*adapters.CommitteeState{uint64(canton): {{
			Qualifier: "default", ChainSelector: uint64(canton), Address: "canton-verifier",
			SignatureConfigs: []adapters.SignatureConfig{{SourceChainSelector: uint64(ethereum), Threshold: 2, Signers: signers}},
		}}}
		inv.AddOnchainCommittees(t.Context(), deployment.Environment{})
	}

	scan(alphaAddr, betaAddr, gammaAddr)
	assert.NotContains(t, inv.Issues, drift, "onchain matching the aggregator has no drift")

	scan(alphaAddr, betaAddr)
	assert.Contains(t, inv.Issues, drift, "the previous matching snapshot cannot mask new drift")

	scan(alphaAddr, betaAddr, gammaAddr)
	assert.NotContains(t, inv.Issues, drift, "a resolved drift alert does not survive the next refresh")
}

func TestAddOnchainCommitteesClearsRemovedNativeVerifier(t *testing.T) {
	adapter := &fakeCommitteeVerifierOnchain{
		discovered: []uint64{uint64(canton)},
		states: map[uint64][]*adapters.CommitteeState{uint64(canton): {{
			Qualifier: "default", ChainSelector: uint64(canton), Address: "canton-verifier",
			SignatureConfigs: []adapters.SignatureConfig{{SourceChainSelector: uint64(ethereum), Threshold: 1, Signers: []string{alphaAddr}}},
		}}},
	}
	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyCanton, adapter)

	// No aggregator config mentions any verifier: discovery alone finds the chain.
	inv := Build(Inputs{})
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{})
	require.NotEmpty(t, committeeFor(t, inv, SourceOnchain, ethereum).Members)

	// The last native ref disappears: the previously scanned chain is still scanned, finds
	// nothing, and its old snapshot is cleared as a removal instead of lingering.
	adapter.discovered = nil
	adapter.states = nil
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{})

	for _, c := range inv.Committees {
		assert.NotEqual(t, SourceOnchain, c.Source, "a chain whose refs were removed loses its old snapshot")
	}
	removed := refreshFor(t, inv, canton)
	assert.Empty(t, removed.LastError, "an empty scan after removal is a success, not a read failure")
	for _, issue := range inv.Issues {
		assert.NotEqual(t, IssueOnchainDrift, issue.Kind, "removed rows leave no drift alerts")
	}
}

func TestAddOnchainCommitteesDiscoversNativeChainsAndCarriesPubKeys(t *testing.T) {
	// A synthetic NOP whose only signer identity is its EVM address: the key comes from the scan.
	key, err := crypto.ToECDSA(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	addr := canonicalSigner("evm", crypto.PubkeyToAddress(key.PublicKey).Hex())
	pub := hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))

	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyCanton, &fakeCommitteeVerifierOnchain{
		// No aggregator config mentions any verifier: only the native ref discovery finds this chain.
		discovered: []uint64{uint64(canton)},
		states: map[uint64][]*adapters.CommitteeState{uint64(canton): {{
			Qualifier: "default", ChainSelector: uint64(canton), Address: "canton-verifier",
			SignatureConfigs: []adapters.SignatureConfig{{
				SourceChainSelector: uint64(ethereum), Threshold: 1, Signers: []string{addr},
				SignerPubKeys: map[string]string{addr: pub},
			}},
		}}},
	})

	in := Inputs{
		Signers: map[string]map[string]string{"nop-delta": {"evm": addr}},
		Nodes:   map[string]NodeRecord{"node_delta": {Name: "nop-delta", CSAKey: "csa-delta"}},
	}
	inv := Build(in)
	inv.AddOnchainCommittees(t.Context(), deployment.Environment{})

	onchain := committeeFor(t, inv, SourceOnchain, ethereum)
	assert.Equal(t, canton, onchain.VerifierChain)
	assert.Equal(t, Member{SignerAddress: addr, SignerPubKey: pub, NOPAlias: "nop-delta", NodeID: "node_delta", CSAKey: "csa-delta"},
		memberFor(t, onchain, addr), "the scanned key fills the pubkey the NOP identity lacks")
	assert.Contains(t, inv.Issues, Issue{
		Kind: IssueOnchainDrift, Subject: "canton-mainnet verifier, source ethereum-mainnet",
		Detail: "no aggregator config has a signer set for this source",
	})

	reconciled := Build(in)
	reconciled.ReconcileOnchainCommittees(inv.Committees, inv.Refreshes)
	assert.Equal(t, pub, memberFor(t, committeeFor(t, reconciled, SourceOnchain, ethereum), addr).SignerPubKey,
		"reconciliation keeps the scanned public key")
	assert.Equal(t, inv.Refreshes, reconciled.Refreshes, "reconciliation keeps the refresh outcomes")
}

func refreshFor(t *testing.T, inv *Inventory, chain ChainSelector) OnchainRefresh {
	t.Helper()
	i := slices.IndexFunc(inv.Refreshes, func(r OnchainRefresh) bool { return r.Chain == chain })
	require.GreaterOrEqual(t, i, 0, "no refresh recorded for %d", chain)
	return inv.Refreshes[i]
}
