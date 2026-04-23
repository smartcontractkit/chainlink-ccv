package adapters

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type VerifierContractAddresses struct {
	CommitteeVerifierAddress string
	OnRampAddress            string
	ExecutorProxyAddress     string
	RMNRemoteAddress         string
}

// VerifierConfigAdapter resolves verifier-related on-chain addresses and the signing
// key family expected for a chain.
type VerifierConfigAdapter interface {
	// ResolveVerifierContractAddresses returns the verifier-related on-chain addresses for
	// the given chain selector. The committee and executor qualifiers identify which
	// deployments to look up in the datastore.
	ResolveVerifierContractAddresses(
		ds datastore.DataStore,
		chainSelector uint64,
		committeeQualifier string,
		executorQualifier string,
	) (*VerifierContractAddresses, error)
	// GetSignerAddressFamily returns the chain-selectors family string whose signing key
	// verifier jobs must use (e.g. chainsel.FamilyEVM for EVM committee verifiers).
	GetSignerAddressFamily() string
}
