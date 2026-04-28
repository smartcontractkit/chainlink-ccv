package adapters

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type TokenVerifierChainAddresses struct {
	OnRampAddress                  string
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
