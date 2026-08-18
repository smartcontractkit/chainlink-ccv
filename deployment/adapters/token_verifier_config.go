package adapters

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type TokenVerifierChainAddresses struct {
	OnRampAddress string
	// RMNRemoteAddress is DEPRECATED: nodes derive the RMN Remote from each ramp's on-chain
	// static config. It is still emitted into generated specs when the datastore has it so
	// the specs keep working for node binaries that predate the derivation cutover; empty
	// when the deployment has no RMN proxy record.
	RMNRemoteAddress               string
	CCTPVerifierAddress            string
	CCTPVerifierResolverAddress    string
	LombardVerifierResolverAddress string
}

// TokenVerifierConfigAdapter resolves the on-chain addresses required to configure
// token verifier services for a chain.
type TokenVerifierConfigAdapter interface {
	// ResolveTokenVerifierAddresses returns the token verifier related addresses for the given
	// chain selector. The cctpQualifier and lombardQualifier identify which deployments to look up.
	ResolveTokenVerifierAddresses(
		ds datastore.DataStore,
		chainSelector uint64,
		cctpQualifier string,
		lombardQualifier string,
	) (*TokenVerifierChainAddresses, error)
}
