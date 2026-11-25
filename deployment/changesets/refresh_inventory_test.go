package changesets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
)

const (
	refreshEthereumSelector = uint64(5009297550715157269)
	refreshCantonSelector   = uint64(2308837218439511688)
	refreshSigner           = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
)

type refreshInventoryOnchainAdapter struct {
	adapters.CommitteeVerifierOnchainAdapter
}

func (refreshInventoryOnchainAdapter) ScanCommitteeStates(
	_ context.Context,
	_ deployment.Environment,
	chain uint64,
) ([]*adapters.CommitteeState, error) {
	return []*adapters.CommitteeState{{
		Qualifier: "default", ChainSelector: chain, Address: "canton-cv",
		SignatureConfigs: []adapters.SignatureConfig{{
			SourceChainSelector: refreshEthereumSelector, Threshold: 1, Signers: []string{refreshSigner},
		}},
	}}, nil
}

func TestRefreshInventoryPersistsAndReconcilesOnchainCommittees(t *testing.T) {
	adapters.GetCommitteeVerifierOnchainRegistry().Register("canton", refreshInventoryOnchainAdapter{})
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveNOPSigners(ds, map[string]map[string]string{"nop-a": {"evm": refreshSigner}}))
	require.NoError(t, ccvdeployment.SaveJDNodes(ds, map[string]ccvdeployment.JDNode{
		"node-a": {Name: "nop-a", CSAKey: "csa-old"},
	}))
	require.NoError(t, ccvdeployment.SaveAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"5009297550715157269": {Signers: []model.Signer{{Address: refreshSigner}}, Threshold: 1},
		},
		DestinationVerifiers: map[model.DestinationSelector]string{"2308837218439511688": "canton-cv"},
	}))
	require.NoError(t, ccvdeployment.SaveAggregatorQualifier(ds, "aggregator-1", "default"))

	out, err := RefreshInventory().Apply(deployment.Environment{DataStore: ds.Seal(), GetContext: t.Context}, RefreshInventoryInput{})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)
	assertOnchainMember(t, out.DataStore.Seal(), "csa-old")

	require.NoError(t, ccvdeployment.SaveJDNodes(out.DataStore, map[string]ccvdeployment.JDNode{
		"node-a": {Name: "nop-a", CSAKey: "csa-new"},
	}))
	assertOnchainMember(t, out.DataStore.Seal(), "csa-new")
}

func assertOnchainMember(t *testing.T, ds datastore.DataStore, csaKey string) {
	t.Helper()
	inv, err := ccvdeployment.GetInventory(ds)
	require.NoError(t, err)
	var onchain []inventory.Committee
	for _, c := range inv.Committees {
		if c.Source == inventory.SourceOnchain {
			onchain = append(onchain, c)
		}
	}
	require.Len(t, onchain, 1)
	assert.Equal(t, inventory.ChainSelector(refreshCantonSelector), onchain[0].VerifierChain)
	require.Len(t, onchain[0].Members, 1)
	assert.Equal(t, inventory.Member{
		SignerAddress: refreshSigner, NOPAlias: "nop-a", NodeID: "node-a", CSAKey: csaKey,
	}, onchain[0].Members[0])
}
