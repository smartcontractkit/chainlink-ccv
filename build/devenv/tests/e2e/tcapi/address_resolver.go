package tcapi

import (
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/addressresolver"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Contract roles and refs (see package addressresolver).
type (
	ContractRole     = addressresolver.ContractRole
	ContractRef      = addressresolver.ContractRef
	AddressResolver  = addressresolver.AddressResolver
	AddressResolvers = addressresolver.Resolvers
)

const (
	RoleMockReceiver              = addressresolver.RoleMockReceiver
	RoleExecutor                  = addressresolver.RoleExecutor
	RoleExecutorImpl              = addressresolver.RoleExecutorImpl
	RoleCommitteeVerifierResolver = addressresolver.RoleCommitteeVerifierResolver
	RoleBurnMintERC20             = addressresolver.RoleBurnMintERC20
)

// ResolveAddress looks up ref on chainSelector using the resolver for that chain's family.
func (d *CaseDeps) ResolveAddress(chainSelector uint64, ref ContractRef) (protocol.UnknownAddress, error) {
	if d == nil {
		return protocol.UnknownAddress{}, addressresolver.ErrResolversRequired
	}
	return addressresolver.Resolve(d.AddressResolvers, d.DataStore, chainSelector, ref)
}

// CommitteeCCV resolves a committee verifier proxy on the source chain as protocol.CCV.
func (d *CaseDeps) CommitteeCCV(chainSelector uint64, qualifier string) (protocol.CCV, error) {
	if d == nil {
		return protocol.CCV{}, addressresolver.ErrResolversRequired
	}
	return addressresolver.CommitteeCCV(d.AddressResolvers, d.DataStore, chainSelector, qualifier)
}
