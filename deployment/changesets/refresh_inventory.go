package changesets

import (
	"errors"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	syncjobproposals "github.com/smartcontractkit/chainlink-ccv/deployment/operations/sync_job_proposals"
)

// RefreshInventoryInput is empty: the refresh uses persisted metadata plus live JD and chain reads.
type RefreshInventoryInput struct{}

// RefreshInventory syncs JD and deployed CommitteeVerifiers before storing the chain-agnostic inventory.
func RefreshInventory() deployment.ChangeSetV2[RefreshInventoryInput] {
	validate := func(e deployment.Environment, _ RefreshInventoryInput) error {
		if e.DataStore == nil {
			return errors.New("datastore is required")
		}
		if e.Offchain == nil {
			return errors.New("offchain client (JD) is required")
		}
		return nil
	}

	apply := func(e deployment.Environment, _ RefreshInventoryInput) (deployment.ChangesetOutput, error) {
		var outputDS datastore.MutableDataStore = datastore.NewMemoryDataStore()
		if err := outputDS.Merge(e.DataStore); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to clone datastore: %w", err)
		}
		syncedDS, err := syncjobproposals.SyncDatastore(e.OperationsBundle, e, outputDS)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to sync JD metadata: %w", err)
		}
		outputDS = syncedDS
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
