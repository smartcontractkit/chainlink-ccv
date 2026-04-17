package evm

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	dsutils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	execop "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	onrampop "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/onramp"
	rmnremote "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type evmVerifierConfigAdapter struct{}

func (a *evmVerifierConfigAdapter) GetSignerAddressFamily() string {
	return chainsel.FamilyEVM
}

func (a *evmVerifierConfigAdapter) ResolveVerifierContractAddresses(
	ds datastore.DataStore,
	chainSelector uint64,
	committeeQualifier string,
	executorQualifier string,
) (*adapters.VerifierContractAddresses, error) {
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

	onRampAddr, err := dsutils.FindAndFormatRef(ds, datastore.AddressRef{
		Type:    datastore.ContractType(onrampop.ContractType),
		Version: onrampop.Version,
	}, chainSelector, toAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get on ramp address for chain %d: %w", chainSelector, err)
	}

	executorAddr, err := dsutils.FindAndFormatRef(ds, datastore.AddressRef{
		Type:      datastore.ContractType(sequences.ExecutorProxyType),
		Qualifier: executorQualifier,
		Version:   execop.Version,
	}, chainSelector, toAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get executor proxy address for chain %d: %w", chainSelector, err)
	}

	rmnRemoteAddr, err := dsutils.FindAndFormatRef(ds, datastore.AddressRef{
		Type:    datastore.ContractType(rmnremote.ContractType),
		Version: rmnremote.Version,
	}, chainSelector, toAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get rmn remote address for chain %d: %w", chainSelector, err)
	}

	return &adapters.VerifierContractAddresses{
		CommitteeVerifierAddress: committeeVerifierAddr,
		OnRampAddress:            onRampAddr,
		ExecutorProxyAddress:     executorAddr,
		RMNRemoteAddress:         rmnRemoteAddr,
	}, nil
}
