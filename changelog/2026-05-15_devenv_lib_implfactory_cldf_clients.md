# Devenv `Lib` as interface, CLDF-backed chain clients, `ImplFactory.New` selector arg

## Executive Summary

- Replaces the exported `ccv.Lib` struct with a `ccv.Lib` interface backed by CCV env output (`NewLibFromCCVEnv`) and/or a raw CLDF environment (`NewLibFromCLDFEnv`), so tests and tools can target the same surface without assuming a concrete type.
- `chainimpl.ImplFactory.New` and `evm.NewCCIP17EVM` no longer build a standalone eth client from `blockchain.Input` / WS URL; they take a **chain selector** and use the **CLDF** `deployment.Environment` EVM chain entry (including `*ethclient.Client` or `*rpcclient.MultiClient` extraction).
- **Breaking:** removes `ccv.NewLib`, removes the global chain-impl registry (`GetGlobalChainImplRegistry` and file `build/devenv/registry/chain_impl.go`), and makes **`Lib.Chains` slice order unspecified** (map iteration over CLDF chains).
- E2E aggregator disablement smokes were updated to pick a `ProgressableChain` with `SupportManualBlockProgress` instead of assuming `chains[0]` matches automine setup.

## AI Adapter Index

The expected consumer of this changelog is an AI adapting a downstream repo. This table is its entry point: every symbol or behavior touched gets one row, with a grep pattern for finding consumer call sites and an anchor into the rest of this file for migration detail. The AI is expected to:

1. Read this table.
2. Run each `Search` pattern against the consumer repo.
3. For rows that produce hits, read **only** the linked `Section`. Skip rows with zero hits.
4. Treat any symbol *not* listed here as unchanged — do not load source for it.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `ccv.NewLib` | removed | `\bccv\.NewLib\b` | — | [#newlib-removed](#newlib-removed) |
| `registry.GetGlobalChainImplRegistry` (and `ChainImplRegistry` helpers) | removed | `GetGlobalChainImplRegistry|ChainImplRegistry` | — | [#global-chain-impl-registry-removed](#global-chain-impl-registry-removed) |
| `chainimpl.ImplFactory.New` | signature-changed | `implements.*ImplFactory|ImplFactory` + manual review of `New\(` | `build/devenv/chainimpl/factory.go:30` | [#implfactory-new-signature](#implfactory-new-signature) |
| `evm.NewCCIP17EVM` | signature-changed | `NewCCIP17EVM\(` | `build/devenv/evm/impl.go:178` | [#newccip17evm-signature](#newccip17evm-signature) |
| `ccv.NewLib` → `ccv.NewLibFromCCVEnv` | renamed | `\bccv\.NewLib\b` (replace with `NewLibFromCCVEnv`) | `build/devenv/lib.go:73` | [#newlibfromccvenv](#newlibfromccvenv) |
| `*ccv.Lib` → `ccv.Lib` (interface) | signature-changed | `\*ccv\.Lib\b` | `build/devenv/lib.go:37` | [#lib-interface-type](#lib-interface-type) |
| `ccv.Lib.Chains` / `ChainsMap` ordering | behavior-changed | `\.Chains\(` when result order assumed | `build/devenv/lib.go:38-39`, `build/devenv/lib.go:203-222` | [#chains-order-unspecified](#chains-order-unspecified) |
| `ccv.NewLibFromCLDFEnv` | added | `NewLibFromCLDFEnv\(` | `build/devenv/lib.go:263` | [#newlibfromcldfenv](#newlibfromcldfenv) |

## Breaking Changes

### `ccv.NewLib` removed; `ccv.Lib` is an interface

- **What changed:** `func NewLib(...) (*Lib, error)` is gone. `Lib` is an interface (`Chains`, `ChainsMap`, `CLDFEnvironment`, `DataStore`, `Indexer`, `AllIndexers`). Concrete types are unexported (`libFromCCV`, `libFromCLDF`).
- **Before:** `lib, err := ccv.NewLib(logger, path, families...)` with `lib` a `*ccv.Lib` struct.
- **After:** `lib, err := ccv.NewLibFromCCVEnv(logger, path, families...)` with `lib` `ccv.Lib` (interface). Optional: `ccv.NewLibFromCLDFEnv(logger, env, families...)` when you already have `*deployment.Environment` and no CCV env file.
- **Why:** Hide implementation details, allow multiple backends (CCV env file vs CLDF-only), and align chain construction with CLDF-hosted clients.
- **Who is affected:** Any consumer importing `github.com/smartcontractkit/chainlink-ccv/build/devenv` and calling `NewLib` or storing `*ccv.Lib`.

### Global chain implementation registry removed

- **What changed:** `build/devenv/registry/chain_impl.go` deleted; `GetGlobalChainImplRegistry`, `ChainImplRegistry.Register`, etc. no longer exist.
- **Before:** Code could register extra `cciptestinterfaces.CCIP17` instances on a global registry; `Lib.Chains` (old behavior) merged cfg chains with registry entries.
- **After:** Chain list comes from the CLDF environment’s chains (`BlockChains.All()`), filtered by `familiesToLoad` when constructing `libFromCLDF`.
- **Why:** Registry + struct `Lib` duplicated sources of truth; CLDF env is the single source for which chains exist and which clients to use.
- **Who is affected:** Downstream tests or tools that called `registry.GetGlobalChainImplRegistry()` to inject or observe extra impls.

### `chainimpl.ImplFactory.New` last parameter: `*blockchain.Input` → `chainSelector uint64`

- **What changed:** `New(ctx, lggr, env, bc *blockchain.Input)` → `New(ctx, lggr, env, chainSelector uint64)`.
- **Before:** Factories used `bc.ChainID` and `bc.Out.Nodes[0].ExternalWSUrl` (or equivalent) to dial the node.
- **After:** Factories must use `env.BlockChains` / `env.DataStore` for the given `chainSelector` (see EVM implementation).
- **Why:** One RPC client per chain is already constructed inside the CLDF environment; avoids duplicate connections and mismatched gas / client settings.
- **Who is affected:** Any repo that implements `chainimpl.ImplFactory` and registers it via `RegisterImplFactory` (per package comment: product repos such as Canton, Stellar, Solana).

### `evm.NewCCIP17EVM` no longer takes `chainID` + `wsURL`

- **What changed:** `NewCCIP17EVM(ctx, logger, env, chainID, wsURL string)` → `NewCCIP17EVM(ctx, logger, env, chainSelector uint64)`.
- **Before:** Opened websocket client via devenv `ETHClient` using `wsURL`.
- **After:** Resolves `cldfChain := env.BlockChains.EVMChains()[chainSelector]`, extracts `*ethclient.Client` from `cldfChain.Client` (`*ethclient.Client` or `*rpcclient.MultiClient`), binds on-ramp/off-ramp to that client.
- **Why:** Same as `ImplFactory.New` — reuse CLDF-managed clients.
- **Who is affected:** Direct callers of `evm.NewCCIP17EVM` outside the bundled `evmImplFactory`.

### `Lib.Chains` return order is unspecified

- **What changed:** `libFromCLDF.Chains` builds the slice by ranging over a map from `ChainsMap` / `BlockChains.All()`; order is not TOML order and not stable across Go versions.
- **Before:** Callers often assumed `chains[0]` was a specific role (e.g. automine “source”).
- **After:** Select chains by selector, capability (`ProgressableChain` + `SupportManualBlockProgress`), or explicit sort if you need determinism.
- **Why:** Map-backed CLDF chain sets do not define a canonical slice order.
- **Who is affected:** Tests and scripts that indexed `lib.Chains(ctx)` by fixed positions.

## Migration Guide

1. **Rename constructor:** Replace `ccv.NewLib(` with `ccv.NewLibFromCCVEnv(` everywhere.
2. **Update types:** Replace `*ccv.Lib` with `ccv.Lib` in structs and function parameters (e.g. test harnesses, helpers).
3. **Stop using the global chain impl registry:** If you injected impls via `GetGlobalChainImplRegistry`, ensure those chains exist in the CLDF `deployment.Environment` passed into `NewCLDFOperationsEnvironment` / `NewLibFromCCVEnv` instead, or construct a `Lib` via `NewLibFromCLDFEnv` with an env you built yourself.
4. **Update custom `ImplFactory` implementations:** Change `New` to accept `chainSelector uint64` and use `env` + selector to obtain chain clients and datastore addresses (mirror `build/devenv/evm_factory.go` and `build/devenv/evm/impl.go`).
5. **Fix ordering-sensitive tests:** After `chains, err := lib.Chains(ctx)`, do not use `chains[0]` unless you sort or select by property (see `build/devenv/tests/e2e/smoke_aggregator_message_disablement_rules_test.go` and `chainSupportingManualBlockProgress`).

```go
// Before
lib, err := ccv.NewLib(logger, envOutPath, chain_selectors.FamilyEVM)
var _ *ccv.Lib = lib

// After
lib, err := ccv.NewLibFromCCVEnv(logger, envOutPath, chain_selectors.FamilyEVM)
var _ ccv.Lib = lib
```

```go
// Before (custom ImplFactory)
func (f *myFactory) New(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, bc *blockchain.Input) (cciptestinterfaces.CCIP17, error) {
	return mychain.New(ctx, lggr, env, bc.ChainID, bc.Out.Nodes[0].ExternalWSUrl)
}

// After
func (f *myFactory) New(ctx context.Context, lggr zerolog.Logger, env *deployment.Environment, chainSelector uint64) (cciptestinterfaces.CCIP17, error) {
	return mychain.New(ctx, lggr, env, chainSelector)
}
```

## New Features / Additions

- **`ccv.NewLibFromCLDFEnv`** — constructs `ccv.Lib` from an existing `*deployment.Environment` without a CCV `env-out` file. Indexer methods return errors (no endpoints on CLDF-only lib). See `build/devenv/lib.go:263`.
  - Usage: phased runtimes or tests that already hold a CLDF env and want `Chains` / `DataStore` / `CLDFEnvironment` without loading TOML.

## Deprecations *(optional)*

- None.

## Compatibility & Requirements *(optional)*

- **EVM client types:** `evm.NewCCIP17EVM` / `extractEthClientFromBackend` support `*ethclient.Client` and `*rpcclient.MultiClient` as the CLDF chain backend client. Other concrete types return a clear error (`unsupported EVM on-chain client type %T`).
- **Module:** Changes live under `github.com/smartcontractkit/chainlink-ccv/build/devenv` (nested `go.mod`). Downstream modules must depend on the same `build/devenv` version they compile against.

## Examples *(optional)*

```go
// CLDF-only library (no env-out.toml)
lib, err := ccv.NewLibFromCLDFEnv(logger, env, chain_selectors.FamilyEVM)
if err != nil {
	return err
}
chains, err := lib.Chains(ctx)
// Do not assume chains[0] is a specific chain; pick by selector or capability.
```

## References *(optional)*

- Prior related entry: `changelog/2026-05-05_remove_chain_curse_api.md` (CLDF env on `Lib` / migration wording may overlap; prefer this file for constructor and interface renames).
