package changesets

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

// withPersistedJDNodeIDs merges registration's durable inventory into the legacy nodes.json allowlist.
func withPersistedJDNodeIDs(e deployment.Environment) (deployment.Environment, error) {
	return ccvdeployment.WithPersistedJDNodeIDs(e)
}
