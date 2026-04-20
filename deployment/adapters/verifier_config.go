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

type VerifierConfigAdapter interface {
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
