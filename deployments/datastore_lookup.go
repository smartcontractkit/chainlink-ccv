package deployments

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// ResolveContractAddress looks up a single contract address from the datastore.
// Returns an error if zero or multiple contracts are found.
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

// CollectContractAddresses looks up contract addresses across multiple chains and returns unique addresses.
// Unlike ResolveContractAddress, this allows zero matches per chain as long as at least one address is found overall.
func CollectContractAddresses(
	ds datastore.DataStore,
	chainSelectors []uint64,
	qualifier string,
	contractType deployment.ContractType,
) ([]string, error) {
	seen := make(map[string]bool)
	addresses := make([]string, 0)

	for _, chainSelector := range chainSelectors {
		refs := ds.Addresses().Filter(
			datastore.AddressRefByChainSelector(chainSelector),
			datastore.AddressRefByQualifier(qualifier),
			datastore.AddressRefByType(datastore.ContractType(contractType)),
		)

		for _, ref := range refs {
			if !seen[ref.Address] {
				seen[ref.Address] = true
				addresses = append(addresses, ref.Address)
			}
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no contracts found for qualifier %q and type %q across %d chains",
			qualifier, contractType, len(chainSelectors))
	}

	return addresses, nil
}
