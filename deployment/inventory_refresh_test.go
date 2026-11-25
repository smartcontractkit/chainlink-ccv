package deployment

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
	indexerconfig "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

func TestInventoryRefreshesOnCCVWrites(t *testing.T) {
	t.Parallel()

	const signer = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	ds := datastore.NewMemoryDataStore()

	require.NoError(t, SaveJDNodes(ds, map[string]JDNode{"node_a": {Name: "nop-a", CSAKey: "csa-a"}}))
	inv := storedInventory(t, ds)
	require.NotNil(t, inv, "a node inventory write stores an inventory")
	require.Len(t, inv.Nodes, 1)
	assert.Empty(t, inv.Committees)

	require.NoError(t, SaveNOPSigners(ds, map[string]map[string]string{"nop-a": {"evm": signer}}))
	require.NoError(t, SaveAggregatorConfig(ds, "aggregator-1", &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"5009297550715157269": {Signers: []model.Signer{{Address: signer}}, Threshold: 1},
		},
	}))
	require.NoError(t, SaveAggregatorQualifier(ds, "aggregator-1", "default"))

	inv = storedInventory(t, ds)
	require.NotNil(t, inv)
	require.Len(t, inv.Committees, 1)
	assert.Equal(t, "default", inv.Committees[0].Qualifier)
	assert.Equal(t, []inventory.Member{{SignerAddress: signer, NOPAlias: "nop-a", NodeID: "node_a", CSAKey: "csa-a"}},
		inv.Committees[0].Members)

	fresh, err := GetInventory(ds.Seal())
	require.NoError(t, err)
	assert.Equal(t, fresh, inv, "the stored copy matches a fresh build")

	envMeta, err := ds.EnvMetadata().Get()
	require.NoError(t, err)
	raw, err := json.Marshal(envMeta.Metadata)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"sourceChainSelector":"5009297550715157269"`, "selectors are stored as strings")
}

func TestInventoryOmittedWithoutInputs(t *testing.T) {
	t.Parallel()

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, SaveIndexerConfig(ds, "indexer-1", &indexerconfig.GeneratedConfig{}))
	assert.Nil(t, storedInventory(t, ds))
}

// storedInventory decodes the inventory persisted in the env metadata, or nil when there is none.
func storedInventory(t *testing.T, ds datastore.MutableDataStore) *inventory.Inventory {
	t.Helper()
	envMeta, err := ds.EnvMetadata().Get()
	require.NoError(t, err)
	raw, err := json.Marshal(envMeta.Metadata)
	require.NoError(t, err)
	var meta struct {
		Inventory *inventory.Inventory `json:"inventory"`
	}
	require.NoError(t, json.Unmarshal(raw, &meta))
	return meta.Inventory
}
