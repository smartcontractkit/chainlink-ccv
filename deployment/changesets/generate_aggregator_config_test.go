package changesets

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
)

const (
	genSignerA = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	genSignerB = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
)

// A normal chain-aware run starting with an empty inventory publishes the observed signer set
// and quorum in env metadata on the first run, and a threshold override never rewrites them.
func TestGenerateAggregatorConfigPublishesObservedCommittees(t *testing.T) {
	selA := chainsel.TEST_90000001.Selector
	selB := chainsel.TEST_90000002.Selector
	registerFullEVMAdapters(&stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{selA: {{
			Qualifier: "default", ChainSelector: selA, Address: "0x0000000000000000000000000000000000000002",
			SignatureConfigs: []adapters.SignatureConfig{{
				SourceChainSelector: selB, Threshold: 2, Signers: []string{genSignerA, genSignerB},
			}},
		}}},
		verifierAddrs: map[uint64]string{selA: "0x0000000000000000000000000000000000000002", selB: "0x0000000000000000000000000000000000000003"},
	})
	env := newTestEnvForApply(t, "nop1", []uint64{selA, selB})
	env.GetContext = t.Context
	override := uint8(5)

	out, err := GenerateAggregatorConfig().Apply(env, GenerateAggregatorConfigInput{
		ServiceIdentifier:  "agg-1",
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{selA, selB},
		ThresholdOverride:  &override,
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	// The generated config carries the override; the observed committee keeps the raw quorum.
	agg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "agg-1")
	require.NoError(t, err)
	require.Contains(t, agg.QuorumConfigs, fmt.Sprint(selB))
	assert.Equal(t, override, agg.QuorumConfigs[fmt.Sprint(selB)].Threshold)

	inv, err := ccvdeployment.GetInventory(out.DataStore.Seal())
	require.NoError(t, err)
	var onchain []inventory.Committee
	for _, c := range inv.Committees {
		if c.Source == inventory.SourceOnchain {
			onchain = append(onchain, c)
		}
	}
	require.Len(t, onchain, 1, "the first run already publishes the observed committee")
	assert.Equal(t, inventory.ChainSelector(selA), onchain[0].VerifierChain)
	assert.Equal(t, inventory.ChainSelector(selB), onchain[0].SourceChain)
	assert.Equal(t, uint8(2), onchain[0].Threshold, "the inventory keeps the onchain quorum, not the override")
	require.Len(t, onchain[0].Members, 2)
	addresses := []string{onchain[0].Members[0].SignerAddress, onchain[0].Members[1].SignerAddress}
	assert.ElementsMatch(t, []string{genSignerA, genSignerB}, addresses)

	require.Len(t, inv.Refreshes, 2, "both scanned chains record a successful refresh")
	for _, refresh := range inv.Refreshes {
		assert.Empty(t, refresh.LastError)
		assert.False(t, refresh.LastSuccessAt.IsZero())
	}
}
