package registration

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

func saveJDNodeInventory(e cldf.Environment, nodes map[string]ccvdeployment.JDNode) (datastore.MutableDataStore, error) {
	ds := datastore.NewMemoryDataStore()
	if e.DataStore != nil {
		if err := ds.Merge(e.DataStore); err != nil {
			return nil, fmt.Errorf("failed to clone datastore: %w", err)
		}
	}
	if err := ccvdeployment.SaveJDNodes(ds, nodes); err != nil {
		return nil, fmt.Errorf("failed to save JD node inventory: %w", err)
	}
	return ds, nil
}
