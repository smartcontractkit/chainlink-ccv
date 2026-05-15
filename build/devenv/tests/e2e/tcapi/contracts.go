package tcapi

import (
	"fmt"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

const (
	DefaultExecTimeout = 40 * time.Second
	DefaultSentTimeout = 10 * time.Second
)

// GetContractAddress returns the contract address for the given chain and contract reference.
func GetContractAddress(ds datastore.DataStore, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) (protocol.UnknownAddress, error) {
	ref, err := ds.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	if err != nil {
		return protocol.UnknownAddress{}, fmt.Errorf("failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s: %w",
			contractName, chainSelector, contractType, version, err)
	}
	return protocol.NewUnknownAddressFromHex(ref.Address)
}
