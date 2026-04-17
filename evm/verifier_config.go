package evm

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type evmVerifierConfigAdapter struct{}

// GetSignerAddressFamily returns the chain-selectors family whose OCR2 signing key
// EVM committee verifier jobs must use.
func (a *evmVerifierConfigAdapter) GetSignerAddressFamily() string {
	return chainsel.FamilyEVM
}

// ResolveVerifierContractAddresses reads EVM committee verifier contract addresses
// (CommitteeVerifier, OnRamp, ExecutorProxy, RMNRemote) from the datastore.
func (a *evmVerifierConfigAdapter) ResolveVerifierContractAddresses(
	ds datastore.DataStore,
	chainSelector uint64,
	committeeQualifier string,
	executorQualifier string,
) (*adapters.VerifierContractAddresses, error) {
	// TODO: resolve addresses from EVM-specific datastore entries for this
	// chainSelector, committeeQualifier, and executorQualifier.
	return nil, fmt.Errorf("EVM verifier config adapter not yet implemented for chain %d", chainSelector)
}
