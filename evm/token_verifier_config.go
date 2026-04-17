package evm

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type evmTokenVerifierConfigAdapter struct{}

// ResolveTokenVerifierAddresses returns the EVM-specific contract addresses needed to
// build the token verifier config (OnRamp, RMNRemote, CCTP/Lombard verifiers and resolvers).
func (a *evmTokenVerifierConfigAdapter) ResolveTokenVerifierAddresses(
	ds datastore.DataStore,
	chainSelector uint64,
	cctpQualifier string,
	lombardQualifier string,
) (*adapters.TokenVerifierChainAddresses, error) {
	// TODO: read OnRamp, RMNRemote, CCTPVerifier, CCTPVerifierResolver,
	// and LombardVerifierResolver addresses from EVM datastore entries.
	return nil, fmt.Errorf("EVM token verifier config adapter not yet implemented for chain %d", chainSelector)
}
