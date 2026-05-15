// Package addressresolver defines the contract-role address lookup used by tcapi test cases.
// It lives under tcapi as a separate package so evmaddr can implement [AddressResolver]
// without importing the parent tcapi package (import cycles).
package addressresolver

import (
	"errors"
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// ErrResolversRequired is returned when address resolver dependencies are missing.
var ErrResolversRequired = errors.New("address resolvers are required")

// ContractRole identifies a logical contract deployed in devenv (family-specific type/version
// are resolved by the AddressResolver for that chain's family).
type ContractRole string

const (
	RoleMockReceiver              ContractRole = "mock_receiver"
	RoleExecutor                  ContractRole = "executor"
	RoleExecutorImpl              ContractRole = "executor_impl"
	RoleCommitteeVerifierResolver ContractRole = "committee_verifier_resolver"
	RoleBurnMintERC20             ContractRole = "burn_mint_erc20"
)

// ContractRef selects a contract on a chain by role and datastore qualifier.
type ContractRef struct {
	Role      ContractRole
	Qualifier string
}

// AddressResolver maps a logical contract reference to an on-chain address for one chain family.
type AddressResolver interface {
	Resolve(ds datastore.DataStore, chainSelector uint64, ref ContractRef) (protocol.UnknownAddress, error)
}

// Resolvers maps chain family (e.g. chainsel.FamilyEVM) to a resolver for that family.
type Resolvers map[string]AddressResolver

// Resolve looks up ref on the chain identified by chainSelector using the resolver for that family.
func Resolve(resolvers Resolvers, ds datastore.DataStore, chainSelector uint64, ref ContractRef) (protocol.UnknownAddress, error) {
	if len(resolvers) == 0 {
		return protocol.UnknownAddress{}, fmt.Errorf("address resolvers map is required")
	}
	family, err := chainsel.GetSelectorFamily(chainSelector)
	if err != nil {
		return protocol.UnknownAddress{}, fmt.Errorf("chain selector %d: %w", chainSelector, err)
	}
	resolver, ok := resolvers[family]
	if !ok || resolver == nil {
		return protocol.UnknownAddress{}, fmt.Errorf("no address resolver for chain family %q (selector %d)", family, chainSelector)
	}
	return resolver.Resolve(ds, chainSelector, ref)
}

// CommitteeCCV resolves a committee verifier proxy as protocol.CCV.
func CommitteeCCV(resolvers Resolvers, ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.CCV, error) {
	addr, err := Resolve(resolvers, ds, chainSelector, ContractRef{
		Role:      RoleCommitteeVerifierResolver,
		Qualifier: qualifier,
	})
	if err != nil {
		return protocol.CCV{}, err
	}
	return protocol.CCV{CCVAddress: addr, Args: []byte{}, ArgsLen: 0}, nil
}

// ValidateResolvers ensures resolvers are present for the source and destination chain families.
func ValidateResolvers(resolvers Resolvers, srcSel, dstSel uint64) error {
	if len(resolvers) == 0 {
		return fmt.Errorf("address resolvers map is required")
	}
	for _, sel := range []uint64{srcSel, dstSel} {
		family, err := chainsel.GetSelectorFamily(sel)
		if err != nil {
			return fmt.Errorf("chain selector %d: %w", sel, err)
		}
		resolver, ok := resolvers[family]
		if !ok || resolver == nil {
			return fmt.Errorf("no address resolver for chain family %q (selector %d)", family, sel)
		}
	}
	return nil
}
