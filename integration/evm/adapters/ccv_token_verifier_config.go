package adapters

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/rmn_proxy"
	onrampop "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	cctpverifier "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_1_0/operations/cctp_verifier"
	lombardverifier "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_1_0/operations/lombard_verifier"
	dsutils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type EVMCCVTokenVerifierConfigAdapter struct{}

var _ ccvdeploymentadapters.TokenVerifierConfigAdapter = (*EVMCCVTokenVerifierConfigAdapter)(nil)

func (a *EVMCCVTokenVerifierConfigAdapter) ResolveTokenVerifierAddresses(
	ds datastore.DataStore,
	chainSelector uint64,
	cctpQualifier string,
	lombardQualifier string,
) (*ccvdeploymentadapters.TokenVerifierChainAddresses, error) {
	toAddress := func(ref datastore.AddressRef) (string, error) { return ref.Address, nil }

	onRampAddr, err := dsutils.FindAndFormatRef(ds, datastore.AddressRef{
		Type:    datastore.ContractType(onrampop.ContractType),
		Version: onrampop.Version,
	}, chainSelector, toAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get on ramp address for chain %d: %w", chainSelector, err)
	}

	result := &ccvdeploymentadapters.TokenVerifierChainAddresses{
		OnRampAddress: onRampAddr,
	}

	// The RMN proxy is resolved best-effort: the field it feeds is deprecated (nodes derive the
	// RMN Remote from the ramps' on-chain static config), so its absence from the datastore is
	// not an error. It is still emitted when present so generated configs keep working for node
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

	cctpVerifierRefs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByType(datastore.ContractType(cctpverifier.ContractType)),
		datastore.AddressRefByQualifier(cctpQualifier),
		datastore.AddressRefByVersion(cctpverifier.Version),
	)
	if len(cctpVerifierRefs) > 1 {
		return nil, fmt.Errorf("chain %d: expected at most 1 CCTPVerifier with qualifier %q, found %d", chainSelector, cctpQualifier, len(cctpVerifierRefs))
	}

	cctpResolverRefs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByType(datastore.ContractType(versioned_verifier_resolver.CCTPVerifierResolverType)),
		datastore.AddressRefByQualifier(cctpQualifier),
		datastore.AddressRefByVersion(versioned_verifier_resolver.Version),
	)
	if len(cctpResolverRefs) > 1 {
		return nil, fmt.Errorf("chain %d: expected at most 1 CCTPVerifierResolver with qualifier %q, found %d", chainSelector, cctpQualifier, len(cctpResolverRefs))
	}

	if (len(cctpVerifierRefs) == 1) != (len(cctpResolverRefs) == 1) {
		return nil, fmt.Errorf(
			"chain %d: CCTP verifier and resolver must both exist or both be absent (verifier found: %v, resolver found: %v)",
			chainSelector, len(cctpVerifierRefs) == 1, len(cctpResolverRefs) == 1,
		)
	}
	if len(cctpVerifierRefs) == 1 {
		result.CCTPVerifierAddress = cctpVerifierRefs[0].Address
		result.CCTPVerifierResolverAddress = cctpResolverRefs[0].Address
	}

	lombardResolverRefs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByType(datastore.ContractType(versioned_verifier_resolver.LombardVerifierResolverType)),
		datastore.AddressRefByQualifier(lombardQualifier),
		datastore.AddressRefByVersion(lombardverifier.Version),
	)
	if len(lombardResolverRefs) > 1 {
		return nil, fmt.Errorf("chain %d: expected at most 1 LombardVerifierResolver with qualifier %q, found %d", chainSelector, lombardQualifier, len(lombardResolverRefs))
	}
	if len(lombardResolverRefs) == 1 {
		result.LombardVerifierResolverAddress = lombardResolverRefs[0].Address
	}

	return result, nil
}
