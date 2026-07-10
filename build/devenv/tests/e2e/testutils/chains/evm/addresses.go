package evm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/stretchr/testify/require"
)

// MustGetDatastoreAddress returns the EVM address of a contract from the datastore for a given chain selector and address ref filter.
func MustGetDatastoreAddress(t *testing.T, ds datastore.DataStore, key datastore.AddressRefKey) common.Address {
	t.Helper()

	ref, err := ds.Addresses().Get(key)
	require.NoError(t, err, "address ref %q on chain %d", key.Qualifier(), key.ChainSelector())
	require.NotEmpty(t, ref.Address, "address ref %q on chain %d is empty", key.Qualifier(), key.ChainSelector())
	require.True(t, common.IsHexAddress(ref.Address), "address ref %q on chain %d is not a valid hex address: %s", key.Qualifier(), key.ChainSelector(), ref.Address)

	return common.HexToAddress(ref.Address)
}

// MustDeployerAddress returns the hex address of the deployer key for an EVM chain.
func MustDeployerAddress(t *testing.T, env *deployment.Environment, sel uint64) string {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	return chain.DeployerKey.From.Hex()
}
