package evm

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// ResolveContractAddr filters the datastore for a single address ref matching the
// given chain selector, contract type, and version. Returns an error if the
// filter does not match exactly one ref.
func ResolveContractAddr(ds datastore.DataStore, selector uint64, contractType datastore.ContractType, version *semver.Version) (common.Address, error) {
	refs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(selector),
		datastore.AddressRefByType(contractType),
		datastore.AddressRefByVersion(version),
	)
	if len(refs) != 1 {
		return common.Address{}, fmt.Errorf("expected 1 %s for selector %d version %s, got %d", contractType, selector, version, len(refs))
	}
	return common.HexToAddress(refs[0].Address), nil
}
