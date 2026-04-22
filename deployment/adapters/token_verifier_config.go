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

type TokenVerifierConfigAdapter interface {
	ResolveTokenVerifierAddresses(
		ds datastore.DataStore,
		chainSelector uint64,
		cctpQualifier string,
		lombardQualifier string,
	) (*TokenVerifierChainAddresses, error)
}
