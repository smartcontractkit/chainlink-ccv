// Package addressresolver defines family-specific address lookup for tcapi test cases.
// It lives as a subpackage so evmaddr can implement [AddressResolver] without importing
// the parent tcapi package (import cycles).
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

// AddressResolver resolves well-known devenv contracts for one chain family.
type AddressResolver interface {
	// GetContractReceiver returns the mock receiver contract address for the given qualifier.
	GetContractReceiver(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)
	// GetExecutor returns the executor proxy address (standard proxy deployment version).
	GetExecutor(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)
	// GetExecutorImpl returns the executor proxy address when registered under the executor-impl deployment version.
	GetExecutorImpl(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)
	// GetCommitteeCCV returns the committee verifier resolver proxy address (not a full protocol.CCV; tests set args).
	GetCommitteeCCV(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)
	// GetBurnMintERC20 returns the burn-mint ERC-20 / ERC-677 token contract address for the pool qualifier.
	GetBurnMintERC20(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)
}

// Resolvers maps chain family (e.g. chainsel.FamilyEVM) to a resolver for that family.
type Resolvers map[string]AddressResolver

// ResolverFor returns the [AddressResolver] for the chain family of chainSelector.
func ResolverFor(resolvers Resolvers, chainSelector uint64) (AddressResolver, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("address resolvers map is required")
	}
	family, err := chainsel.GetSelectorFamily(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("chain selector %d: %w", chainSelector, err)
	}
	r, ok := resolvers[family]
	if !ok || r == nil {
		return nil, fmt.Errorf("no address resolver for chain family %q (selector %d)", family, chainSelector)
	}
	return r, nil
}

// ValidateResolvers ensures resolvers are present for the source and destination chain families.
func ValidateResolvers(resolvers Resolvers, srcSel, dstSel uint64) error {
	if len(resolvers) == 0 {
		return fmt.Errorf("address resolvers map is required")
	}
	for _, sel := range []uint64{srcSel, dstSel} {
		if _, err := ResolverFor(resolvers, sel); err != nil {
			return err
		}
	}
	return nil
}
