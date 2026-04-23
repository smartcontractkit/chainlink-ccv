package evm

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	cctpverifier "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/cctp_verifier"
	lombardverifier "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/lombard_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldfdeployment "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type evmIndexerConfigAdapter struct{}

func (a *evmIndexerConfigAdapter) ResolveVerifierAddresses(
	ds datastore.DataStore,
	chainSelector uint64,
	qualifier string,
	kind adapters.VerifierKind,
) ([]string, error) {
	resolverType, version, err := resolveIndexerContractMeta(kind)
	if err != nil {
		return nil, err
	}

	refs := ds.Addresses().Filter(
		datastore.AddressRefByChainSelector(chainSelector),
		datastore.AddressRefByQualifier(qualifier),
		datastore.AddressRefByType(datastore.ContractType(resolverType)),
		datastore.AddressRefByVersion(version),
	)

	if len(refs) == 0 {
		return nil, &adapters.MissingIndexerVerifierAddressesError{
			Kind:          kind,
			ChainSelector: chainSelector,
			Qualifier:     qualifier,
		}
	}

	addresses := make([]string, 0, len(refs))
	for _, r := range refs {
		addresses = append(addresses, r.Address)
	}

	return addresses, nil
}

func resolveIndexerContractMeta(kind adapters.VerifierKind) (cldfdeployment.ContractType, *semver.Version, error) {
	switch kind {
	case adapters.CommitteeVerifierKind:
		return versioned_verifier_resolver.CommitteeVerifierResolverType, versioned_verifier_resolver.Version, nil
	case adapters.CCTPVerifierKind:
		return versioned_verifier_resolver.CCTPVerifierResolverType, cctpverifier.Version, nil
	case adapters.LombardVerifierKind:
		return versioned_verifier_resolver.LombardVerifierResolverType, lombardverifier.Version, nil
	default:
		return "", nil, fmt.Errorf("unknown verifier kind %q", kind)
	}
}
