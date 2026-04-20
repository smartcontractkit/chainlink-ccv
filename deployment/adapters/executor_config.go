package adapters

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/executor"
)

// ExecutorConfigAdapter resolves per-chain executor configuration from the datastore.
// BuildChainConfig returns executor.ChainConfiguration directly — no intermediate copy type needed.
type ExecutorConfigAdapter interface {
	GetDeployedChains(ds datastore.DataStore, qualifier string) []uint64
	BuildChainConfig(ds datastore.DataStore, chainSelector uint64, qualifier string) (executor.ChainConfiguration, error)
}
