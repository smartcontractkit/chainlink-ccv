package adapters

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/rmn_proxy"
	onrampop "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	dsutils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type EVMCCVVerifierConfigAdapter struct{}

var _ ccvdeploymentadapters.VerifierConfigAdapter = (*EVMCCVVerifierConfigAdapter)(nil)

func (a *EVMCCVVerifierConfigAdapter) GetSignerAddressFamily() string {
	return chainsel.FamilyEVM
}

func (a *EVMCCVVerifierConfigAdapter) ResolveVerifierContractAddresses(
	ds datastore.DataStore,
	chainSelector uint64,
	committeeQualifier string,
	executorQualifier string,
) (*ccvdeploymentadapters.VerifierContractAddresses, error) {
	toAddress := func(ref datastore.AddressRef) (string, error) { return ref.Address, nil }

	committeeVerifierAddr, err := dsutils.FindAndFormatFirstRef(ds, chainSelector, toAddress,
		datastore.AddressRef{
			Type:      datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
			Qualifier: committeeQualifier,
		},
		datastore.AddressRef{
			Type:      datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierContractType),
			Qualifier: committeeQualifier,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get committee verifier address for chain %d: %w", chainSelector, err)
	}

	onRampAddr, err := dsutils.FindAndFormatCanonicalRef(ds, datastore.AddressRef{
		Type:    datastore.ContractType(onrampop.ContractType),
		Version: onrampop.Version,
	}, chainSelector, toAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get on ramp address for chain %d: %w", chainSelector, err)
	}

	result := &ccvdeploymentadapters.VerifierContractAddresses{
		CommitteeVerifierAddress: committeeVerifierAddr,
		OnRampAddress:            onRampAddr,
	}

	// The RMN proxy is resolved best-effort: the field it feeds is deprecated (nodes derive the
	// RMN Remote from the ramps' on-chain static config), so its absence from the datastore is
	// not an error. It is still emitted when present so generated specs keep working for node
	// binaries that predate the derivation cutover.
	rmnProxyRefs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByType(datastore.ContractType(rmn_proxy.ContractType)),
		datastore.AddressRefByVersion(rmn_proxy.Version),
	)
	if len(rmnProxyRefs) > 1 {
		return nil, fmt.Errorf("chain %d: expected at most 1 RMNProxy, found %d", chainSelector, len(rmnProxyRefs))
	}
	if len(rmnProxyRefs) == 1 {
		result.RMNRemoteAddress = rmnProxyRefs[0].Address
	}

	return result, nil
}
