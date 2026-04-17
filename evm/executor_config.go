package evm

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/executor"
)

type evmExecutorConfigAdapter struct{}

// GetDeployedChains returns EVM chain selectors that have executor contracts deployed
// for the given qualifier, as recorded in the datastore.
func (a *evmExecutorConfigAdapter) GetDeployedChains(ds datastore.DataStore, qualifier string) []uint64 {
	// TODO: query EVM contract addresses from the datastore keyed by qualifier.
	return nil
}

// BuildChainConfig reads EVM-specific contract addresses from the datastore and returns
// the executor chain configuration for the given chain selector and qualifier.
func (a *evmExecutorConfigAdapter) BuildChainConfig(ds datastore.DataStore, chainSelector uint64, qualifier string) (executor.ChainConfiguration, error) {
	// TODO: resolve OffRampAddress, RmnAddress, DefaultExecutorAddress from the
	// EVM-specific datastore entries for this chainSelector and qualifier.
	return executor.ChainConfiguration{}, fmt.Errorf("EVM executor config adapter not yet implemented for chain %d", chainSelector)
}
