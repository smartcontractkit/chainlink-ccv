package adapters

import (
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// RemoveRemotePoolInput is the per-chain input for removing a single remote pool
// from a token pool. The adapter resolves the local token pool address from the
// token: callers supply the token, not the pool.
type RemoveRemotePoolInput struct {
	// ChainSelector is the chain the token pool lives on.
	ChainSelector uint64
	// TokenAddress is the token whose pool is being reconfigured, in the chain
	// family's native string form (EVM hex, Solana base58, etc.). The adapter
	// resolves the active pool for this token from the TokenAdminRegistry.
	TokenAddress string
	// RemoteChainSelector is the remote chain whose pool entry is being removed.
	RemoteChainSelector uint64
	// RemotePoolAddress is the remote pool to remove, in the remote family's
	// native byte encoding. This is resolved by the changeset via the remote
	// chain's adapter (ResolveRemotePoolAddress) so callers never hand-encode a
	// derived address such as a Solana PDA; the adapter matches it against the
	// pool's currently configured remote pools for RemoteChainSelector.
	RemotePoolAddress []byte
	// RegistryAddress optionally overrides the TokenAdminRegistry used to resolve
	// the pool, in the chain family's native string form. Empty resolves the
	// registry from ExistingAddresses.
	RegistryAddress string
	// ExistingAddresses are the deployed addresses on ChainSelector, used by the
	// adapter to resolve the TokenAdminRegistry (and any other local contracts).
	// The changeset populates this from the environment datastore.
	ExistingAddresses []datastore.AddressRef
}

// RemoveRemotePoolOutput is the output of a RemoveRemotePool sequence.
type RemoveRemotePoolOutput struct {
	// BatchOps are MCMS batch operations for proposals. Empty in deployer-key mode
	// (the removal is submitted directly and confirmed on chain).
	BatchOps []mcmstypes.BatchOperation
}

// TokenPoolOnchainAdapter handles onchain token pool reconfiguration on a single
// chain. Implementations are chain-family-specific and registered via Registry.
//
// The adapter's RemoveRemotePool sequence must return a clear error when the
// requested remote pool is not currently configured for the token on
// RemoteChainSelector, rather than emitting a no-op transaction.
type TokenPoolOnchainAdapter interface {
	// RemoveRemotePool returns the per-family sequence that removes a single
	// remote pool from the token's pool on one chain.
	RemoveRemotePool() *operations.Sequence[RemoveRemotePoolInput, RemoveRemotePoolOutput, chain.BlockChains]

	// ResolveRemotePoolAddress returns the on-chain remote-pool-address bytes that
	// a counterpart chain stores to reference the pool serving tokenAddress on
	// chainSelector. It is called on the *remote* chain's adapter so each family
	// encodes (and, where the pool address is derived rather than deployed — e.g.
	// Solana PDAs, derives) its own pool address. This keeps operators from having
	// to hand-specify a remote pool address, which is bug-prone across families.
	//
	// tokenAddress is the token on chainSelector in that chain family's native
	// string form. Implementations resolve the token's active pool (via the
	// TokenAdminRegistry or equivalent) and return the bytes the counterpart pool
	// uses to reference it.
	ResolveRemotePoolAddress(e deployment.Environment, chainSelector uint64, tokenAddress string) ([]byte, error)
}
