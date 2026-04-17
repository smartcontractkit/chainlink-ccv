package evm

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type evmIndexerConfigAdapter struct{}

// ResolveVerifierAddresses returns the EVM verifier contract addresses of the given kind
// (committee, cctp, lombard) for the given chain and qualifier from the datastore.
func (a *evmIndexerConfigAdapter) ResolveVerifierAddresses(ds datastore.DataStore, chainSelector uint64, qualifier string, kind adapters.VerifierKind) ([]string, error) {
	// TODO: read verifier addresses from EVM datastore entries for this
	// chainSelector, qualifier, and verifier kind.
	return nil, &adapters.MissingIndexerVerifierAddressesError{
		Kind:          kind,
		ChainSelector: chainSelector,
		Qualifier:     qualifier,
	}
}
