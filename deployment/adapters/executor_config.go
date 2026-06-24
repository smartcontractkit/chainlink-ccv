package adapters

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/executor"
)

// ExecutorConfigAdapter resolves per-chain executor configuration from the datastore.
// BuildChainConfig returns executor.ChainConfiguration directly — no intermediate copy type needed.
type ExecutorConfigAdapter interface {
	// GetDeployedChains returns the chain selectors that have an executor deployed for the
	// given qualifier in the provided datastore.
	GetDeployedChains(ds datastore.DataStore, qualifier string) []uint64
	// BuildChainConfig builds the executor chain configuration for the given chain selector
	// and qualifier from addresses recorded in the datastore.
	BuildChainConfig(ds datastore.DataStore, chainSelector uint64, qualifier string) (executor.ChainConfiguration, error)
}

// ExecutorNodeChainJDSupport is an optional extension of ExecutorConfigAdapter.
// Implement it to opt out of JD node chain support validation in ApplyExecutorConfig.
//
// RequiresNodeChainSupportInJD reports whether ApplyExecutorConfig must verify that
// target NOPs have this chain registered in JD (ListNodeChainConfigs) before proposing
// ccvexecutor job specs. EVM chains require JD registration; families such as Canton
// that push destination blocks onto existing EVM executor jobs may return false until
// JD node chain configs exist for that family.
//
// Adapters that do not implement ExecutorNodeChainJDSupport default to true (require JD).
type ExecutorNodeChainJDSupport interface {
	RequiresNodeChainSupportInJD() bool
}

// ExecutorRequiresNodeChainSupportInJD returns whether the adapter requires JD node chain
// support validation. Adapters without ExecutorNodeChainJDSupport default to true.
func ExecutorRequiresNodeChainSupportInJD(adapter ExecutorConfigAdapter) bool {
	if a, ok := adapter.(ExecutorNodeChainJDSupport); ok {
		return a.RequiresNodeChainSupportInJD()
	}
	return true
}
