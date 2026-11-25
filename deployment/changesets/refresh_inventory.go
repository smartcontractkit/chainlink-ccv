package changesets

import (
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

// RefreshInventoryInput is empty: the refresh uses the environment's persisted metadata and chains.
type RefreshInventoryInput struct{}

// RefreshInventory reads deployed CommitteeVerifiers and stores the resulting chain-agnostic inventory.
func RefreshInventory() deployment.ChangeSetV2[RefreshInventoryInput] {
	validate := func(e deployment.Environment, _ RefreshInventoryInput) error {
		if e.DataStore == nil {
			return errors.New("datastore is required")
		}
		return nil
	}

	apply := func(e deployment.Environment, _ RefreshInventoryInput) (deployment.ChangesetOutput, error) {
		outputDS := datastore.NewMemoryDataStore()
		if err := outputDS.Merge(e.DataStore); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to clone datastore: %w", err)
		}
		inv, err := ccvdeployment.GetInventory(outputDS.Seal())
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to load inventory: %w", err)
		}
		refreshEnv := e
		refreshEnv.DataStore = outputDS.Seal()
		inv.AddOnchainCommittees(e.GetContext(), refreshEnv)
		if err := ccvdeployment.SaveInventory(outputDS, inv); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to save inventory: %w", err)
		}
		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
