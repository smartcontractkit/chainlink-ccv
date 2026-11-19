package changesets

import (
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

// withPersistedJDNodeIDs merges registration's durable inventory into the legacy nodes.json allowlist.
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

	seen := make(map[string]struct{}, len(e.NodeIDs)+len(nodes))
	for _, nodeID := range e.NodeIDs {
		seen[nodeID] = struct{}{}
	}
	missing := make([]string, 0, len(nodes))
	for nodeID := range nodes {
		if _, ok := seen[nodeID]; !ok {
			missing = append(missing, nodeID)
		}
	}
	slices.Sort(missing)
	e.NodeIDs = append(e.NodeIDs, missing...)
	return e, nil
}
