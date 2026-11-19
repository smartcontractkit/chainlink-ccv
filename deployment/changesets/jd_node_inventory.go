package changesets

import (
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

// withPersistedJDNodeIDs prefers registration's durable inventory over the legacy nodes.json allowlist.
func withPersistedJDNodeIDs(e deployment.Environment) (deployment.Environment, error) {
	if e.Offchain == nil || e.DataStore == nil {
		return e, nil
	}
	nodes, err := ccvdeployment.GetJDNodes(e.DataStore)
	if err != nil {
		return e, fmt.Errorf("failed to load persisted JD node inventory: %w", err)
	}
	if len(nodes) == 0 {
		return e, nil
	}

	e.NodeIDs = make([]string, 0, len(nodes))
	for nodeID := range nodes {
		e.NodeIDs = append(e.NodeIDs, nodeID)
	}
	slices.Sort(e.NodeIDs)
	return e, nil
}
