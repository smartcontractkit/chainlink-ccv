// Package evmaddr implements [addressresolver.AddressResolver] for EVM devenv deployments.
package evmaddr

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc20_with_drip"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/addressresolver"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

func getContractAddress(ds datastore.DataStore, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) (protocol.UnknownAddress, error) {
	ref, err := ds.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	if err != nil {
		return protocol.UnknownAddress{}, fmt.Errorf("failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s: %w",
			contractName, chainSelector, contractType, version, err)
	}
	return protocol.NewUnknownAddressFromHex(ref.Address)
}

// Resolver implements [addressresolver.AddressResolver] for EVM chains using v2.0.0 devenv deployments.
type Resolver struct{}

// New returns an [addressresolver.AddressResolver] for EVM chains.
func New() addressresolver.AddressResolver {
	return Resolver{}
}

// Resolve implements [addressresolver.AddressResolver].
func (Resolver) Resolve(ds datastore.DataStore, chainSelector uint64, ref addressresolver.ContractRef) (protocol.UnknownAddress, error) {
	switch ref.Role {
	case addressresolver.RoleMockReceiver:
		return getContractAddress(ds, chainSelector,
			datastore.ContractType(mock_receiver_v2.ContractType),
			mock_receiver_v2.Deploy.Version(),
			ref.Qualifier,
			"mock receiver",
		)
	case addressresolver.RoleExecutor:
		return getContractAddress(ds, chainSelector,
			datastore.ContractType(sequences.ExecutorProxyType),
			proxy.Deploy.Version(),
			ref.Qualifier,
			"executor",
		)
	case addressresolver.RoleExecutorImpl:
		return getContractAddress(ds, chainSelector,
			datastore.ContractType(sequences.ExecutorProxyType),
			executor.Deploy.Version(),
			ref.Qualifier,
			"executor",
		)
	case addressresolver.RoleCommitteeVerifierResolver:
		return getContractAddress(ds, chainSelector,
			datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
			versioned_verifier_resolver.Version.String(),
			ref.Qualifier,
			"committee verifier proxy",
		)
	case addressresolver.RoleBurnMintERC20:
		return getContractAddress(ds, chainSelector,
			datastore.ContractType(burn_mint_erc20_with_drip.ContractType),
			burn_mint_erc20_with_drip.Deploy.Version(),
			ref.Qualifier,
			"burn mint erc677",
		)
	default:
		return protocol.UnknownAddress{}, fmt.Errorf("evmaddr: unsupported contract role %q", ref.Role)
	}
}
