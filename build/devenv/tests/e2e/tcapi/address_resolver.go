package tcapi

import (
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/addressresolver"
)

type (
	AddressResolver  = addressresolver.AddressResolver
	AddressResolvers = addressresolver.Resolvers
)

// ResolverAt returns the [AddressResolver] for the chain family of chainSelector.
func (d *CaseDeps) ResolverAt(chainSelector uint64) (AddressResolver, error) {
	if d == nil || len(d.AddressResolvers) == 0 {
		return nil, addressresolver.ErrResolversRequired
	}
	return addressresolver.ResolverFor(d.AddressResolvers, chainSelector)
}
