package shared

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// ResolveContractAddress looks up a single contract address from the datastore
// using the provided chain selector, qualifier, and contract type.
// It returns an error if no contract is found or if multiple contracts are found.
func ResolveContractAddress(
	ds datastore.DataStore,
	chainSelector uint64,
	qualifier string,
	contractType deployment.ContractType,
) (string, error) {
	refs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByQualifier(qualifier),
		datastore.AddressRefByType(datastore.ContractType(contractType)),
	)

	if len(refs) == 0 {
		return "", fmt.Errorf("no contract found for chain %d with qualifier %q and type %q",
			chainSelector, qualifier, contractType)
	}

	if len(refs) > 1 {
		return "", fmt.Errorf("multiple contracts found for chain %d with qualifier %q and type %q",
			chainSelector, qualifier, contractType)
	}

	return refs[0].Address, nil
}
