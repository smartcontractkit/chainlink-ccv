# Remove Remote Pool top-level changeset

## Executive Summary

- Adds `RemoveRemotePool`, a single-entry, onchain-only changeset that removes one remote pool entry from a token's pool on a chain. It is the inverse of the implicit `AddRemotePool` step inside `ConfigureTokensForTransfers`, which had no removal counterpart (CCIP-11926).
- Adds a new chain-family adapter interface, `TokenPoolOnchainAdapter`, and its EVM implementation. The changeset dispatches by chain family through a new `GetTokenPoolOnchainRegistry` singleton, mirroring the lane and committee-verifier onchain adapters.
- Operators identify the remote pool by the *remote token*, not by a raw remote pool address. The changeset asks the remote chain's adapter (`ResolveRemotePoolAddress`) to resolve its own pool address, so chain families whose pool address is derived rather than deployed (e.g. Solana PDAs) resolve it themselves and operators never hand-encode one. An explicit `RemotePoolAddress` override remains for removing a specific/stale entry.
- The local adapter resolves the token's active pool from the TokenAdminRegistry, verifies the resolved remote pool is currently configured (clear error if not), then issues `removeRemotePool`. Deployer-key mode submits directly; MCMS mode packages the write into a timelock proposal via the shared `OutputBuilder`.
- The `remove_remote_pool_cross_family` pipeline is registered in `chainlink-deployments/domains/ccv`. That registration compiles once chainlink-ccv is released and the domain bumps its `chainlink-ccv/deployment` dependency.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `adapters.TokenPoolOnchainAdapter` | added | `\bTokenPoolOnchainAdapter\b` | `deployment/adapters/token_pool_onchain.go` | [#tokenpoolonchainadapter](#tokenpoolonchainadapter) |
| `adapters.TokenPoolOnchainAdapter.ResolveRemotePoolAddress` | added | `\bResolveRemotePoolAddress\b` | `deployment/adapters/token_pool_onchain.go` | [#tokenpoolonchainadapter](#tokenpoolonchainadapter) |
| `adapters.RemoveRemotePoolInput` | added | `\bRemoveRemotePoolInput\b` | `deployment/adapters/token_pool_onchain.go:12` | [#tokenpoolonchainadapter](#tokenpoolonchainadapter) |
| `adapters.RemoveRemotePoolOutput` | added | `\bRemoveRemotePoolOutput\b` | `deployment/adapters/token_pool_onchain.go:37` | [#tokenpoolonchainadapter](#tokenpoolonchainadapter) |
| `adapters.GetTokenPoolOnchainRegistry` | added | `\bGetTokenPoolOnchainRegistry\b` | `deployment/adapters/registry.go` | [#tokenpoolonchainadapter](#tokenpoolonchainadapter) |
| `changesets.RemoveRemotePool` | added | `\bRemoveRemotePool\b` | `deployment/changesets/remove_remote_pool.go` | [#removeremotepool-changeset](#removeremotepool-changeset) |
| `changesets.RemoveRemotePoolInput` | added | `RemoveRemotePoolInput{` | `deployment/changesets/remove_remote_pool.go` | [#removeremotepool-changeset](#removeremotepool-changeset) |
| `adapters.EVMCCVTokenPoolOnchainAdapter` | added | `\bEVMCCVTokenPoolOnchainAdapter\b` | `integration/evm/adapters/ccv_token_pool_onchain.go` | [#evm-implementation](#evm-implementation) |

## TokenPoolOnchainAdapter

New per-chain-family interface in `deployment/adapters/token_pool_onchain.go`:

```go
type TokenPoolOnchainAdapter interface {
	RemoveRemotePool() *operations.Sequence[RemoveRemotePoolInput, RemoveRemotePoolOutput, chain.BlockChains]
	ResolveRemotePoolAddress(e deployment.Environment, chainSelector uint64, tokenAddress string) ([]byte, error)
}
```

`RemoveRemotePool` runs on the *local* chain (the pool being modified).
`ResolveRemotePoolAddress` is called on the *remote* chain's adapter to resolve, for
the pool serving `tokenAddress`, the address bytes a counterpart chain stores to
reference it — each family encodes (and, for derived addresses like Solana PDAs,
derives) its own. This is why operators supply the remote token rather than a raw
remote pool address.

`RemoveRemotePoolInput` (the sequence input) carries the token (family-native
string), local chain selector, remote chain selector, the resolved remote pool
address bytes, an optional `RegistryAddress` override, and `ExistingAddresses`
(populated by the changeset from the datastore). `RemoveRemotePoolOutput` carries the
MCMS `BatchOps` (empty in deployer-key mode). Register an implementation per family
with `GetTokenPoolOnchainRegistry().Register(family, impl)`.

Implementing this interface for a non-EVM family is additive — nothing existing
depends on it yet. A Solana implementation would derive the pool PDA from the token
mint in `ResolveRemotePoolAddress` (see `DeriveTokenPoolCounterpart` in the
chainlink-ccip Solana token adapter).

## RemoveRemotePool changeset

`changesets.RemoveRemotePool()` in `deployment/changesets/remove_remote_pool.go`
takes the local token, local + remote chain selectors, and the remote token. It
resolves the remote pool via the remote chain's adapter (unless an explicit
`RemotePoolAddress` override is given), dispatches removal to the local chain's
`TokenPoolOnchainAdapter`, and builds the output with
`ccipchangesets.NewOutputBuilder(...).Build(mcms)`. Set `RemoveRemotePoolInput.MCMS`
to package the removal into a timelock proposal; leave it nil for deployer-key
execution. A clear error is returned when the resolved remote pool is not currently
configured for the token on the remote chain.

## EVM implementation

`EVMCCVTokenPoolOnchainAdapter` in
`integration/evm/adapters/ccv_token_pool_onchain.go` resolves the pool from the
token via `token_admin_registry.GetTokenConfig`, reads `token_pool.GetRemotePools`
to verify the target is configured (left-padding the address to 32 bytes to match
on-chain encoding), and issues `token_pool.RemoveRemotePool`. Registered for the EVM
family in `integration/evm/adapters/init.go`.
