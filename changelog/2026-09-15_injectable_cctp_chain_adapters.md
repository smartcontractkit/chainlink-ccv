# Injectable CCTP chain adapters

## Executive Summary

- This change makes each chain family supply its own CCTP adapter. The adapter gives the domain lookup, the transaction-hash codec, and the address codec.
- Before this change the CCTP verifier held chain knowledge in the core package. A static `Domains` map mapped a chain selector to a Circle domain. Two functions branched on the chain family to pick base58 for Solana and hex for EVM.
- Affected code: `verifier/pkg/token/cctp`. Affected consumers: every binary that verifies CCTP for a non-EVM source chain. `chainlink-ccip-solana` is one example.
- Headline impact: this is a breaking behavior change. A CCTP source chain of a family that has no registered adapter now fails at `Fetch`. The EVM-only token verifier is not affected.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cctp.encodeTxHash` | removed | `\bencodeTxHash\b` | `verifier/pkg/token/cctp/attestation.go:191` | [#chain-codecs-moved-out-of-the-core-package](#chain-codecs-moved-out-of-the-core-package) |
| `cctp.decodeAddress` | removed | `\bdecodeAddress\b` | `verifier/pkg/token/cctp/attestation.go:205` | [#chain-codecs-moved-out-of-the-core-package](#chain-codecs-moved-out-of-the-core-package) |
| `cctp.HTTPAttestationService.Fetch` | behavior-changed | `NewAttestationService\(` | `verifier/pkg/token/cctp/attestation.go:90` | [#fetch-resolves-the-adapter](#fetch-resolves-the-adapter) |
| `cctp.Domains` | behavior-changed | `cctp\.Domains\b` | `verifier/pkg/token/cctp/consts.go:21` | [#domains-stays-the-evm-catalog](#domains-stays-the-evm-catalog) |
| `cctp.ChainAdapter` | added | `\bChainAdapter\b` | `verifier/pkg/token/cctp/adapter.go:19` | [#register-a-family-adapter](#register-a-family-adapter) |
| `cctp.RegisterAdapter` | added | `\bRegisterAdapter\b` | `verifier/pkg/token/cctp/adapter.go:33` | [#register-a-family-adapter](#register-a-family-adapter) |
| `cctp.AdapterFor` | added | `\bAdapterFor\b` | `verifier/pkg/token/cctp/adapter.go:44` | [#register-a-family-adapter](#register-a-family-adapter) |

## Breaking Changes

### A source chain family must register a CCTP adapter

- **What changed:** `HTTPAttestationService.Fetch` and `cctpMatchesMessage` resolve the chain adapter through `AdapterFor(sourceChainSelector)`. The core package no longer branches on the chain family.
- **Before:** the core package held the domain lookup and both codecs. EVM and Solana sources worked with no registration.
- **After:** `Fetch` returns an error for a source chain family that has no registered adapter. The error occurs at `Fetch`, not at startup.
- **Why:** a chain family owns its CCTP facts. A family adds a codec without a change in the core package.
- **Who is affected:** a binary that verifies CCTP for a non-EVM source chain and does not register an adapter. In practice this is the Solana CCTP token verifier. The EVM-only token verifier is not affected. ccv registers the EVM adapter from the package `init()`.

### Chain codecs moved out of the core package

- **What changed:** `encodeTxHash` and `decodeAddress` are gone from the core package.
- **Before:** each function called `chainsel.GetSelectorFamily` and branched to base58 or hex.
- **After:** the codec is a method on the registered adapter. `adapter.EncodeTxHash` and `adapter.DecodeAddress` replace the two functions.
- **Why:** the `TODO` at `verifier/pkg/token/cctp/attestation.go:177` asked for a per-family codec.
- **Who is affected:** no consumer. Both functions were unexported.

### Fetch resolves the adapter

- **What changed:** `Fetch` calls `AdapterFor(message.SourceChainSelector)`. It then calls `adapter.Domain` and `adapter.EncodeTxHash`.
- **Before:** `Fetch` read `Domains[uint64(message.SourceChainSelector)]` and called `encodeTxHash`.
- **After:** the same data comes from the adapter. The error message changes for an unknown selector.
- **Why:** the core path must not hold a chain-specific branch.
- **Who is affected:** a consumer that matches on the old error string `unsupported source chain selector`.

### Domains stays the EVM catalog

- **What changed:** `cctp.Domains` stays exported and stays populated. The EVM adapter reads it.
- **Before:** `Domains` was the single source for every family.
- **After:** `Domains` remains the EVM and Circle catalog. It no longer drives a non-EVM family. A non-EVM family holds its own domain table in its adapter.
- **Why:** a chain repo owns its chain data. `build/devenv` and tooling keep using `Domains`.
- **Who is affected:** no compile break. A reader of `Domains` for a non-EVM selector sees the same value, but that value no longer reaches the verifier path.

## Migration Guide

Do nothing for an EVM-only token verifier.

For a non-EVM family, do these steps. The example is Solana.

1. Implement `cctp.ChainAdapter` in the family repository.
2. Register the implementation from a package `init()`.
3. Blank-import the package that holds the `init()` in the token verifier `main.go`.

```go
// After — pkg/cctp/adapter.go in the family repository
func init() {
	ccvcctp.RegisterAdapter(chainsel.FamilySolana, solanaAdapter{})
}
```

```go
// After — cmd/tokenverifier/main.go in the family repository
import (
	_ "github.com/smartcontractkit/chainlink-ccip-solana/pkg/accessors" // solana accessor driver
	_ "github.com/smartcontractkit/chainlink-ccip-solana/pkg/cctp"      // solana CCTP adapter
)
```

`chainlink-ccip-solana` does these steps in `pkg/cctp/adapter.go` and `cmd/tokenverifier/main.go`.

## Register a family adapter

`verifier/pkg/token/cctp/adapter.go` holds the contract and the registry.

```go
// ChainAdapter holds the chain-specific CCTP facts for one chain family.
type ChainAdapter interface {
	Domain(selector protocol.ChainSelector) (uint32, bool)
	EncodeTxHash(txHash protocol.ByteSlice) (string, error)
	DecodeAddress(address string) (protocol.UnknownAddress, error)
}
```

`RegisterAdapter` stores one adapter per `chainsel` family name. It panics on a nil adapter and on a duplicate registration. `AdapterFor` resolves the adapter for a selector through `chainsel.GetSelectorFamily`.

The EVM adapter is `verifier/pkg/token/cctp/adapter_evm.go`. It registers `chainsel.FamilyEVM` from `init()`, and it reads the `Domains` catalog.

## New Features / Additions

- **`cctp.ChainAdapter`** — the chain-family contract. See `verifier/pkg/token/cctp/adapter.go`.
- **`cctp.RegisterAdapter`** — family registration. Call it from a package `init()`.
- **`cctp.AdapterFor`** — selector to adapter resolution.
- **EVM adapter** — `verifier/pkg/token/cctp/adapter_evm.go`.

## Compatibility & Requirements

- **Rollout:** ship the family binary with the family adapter before the core change reaches the family. A binary without an adapter fails every CCTP attestation for that family.
- **Rollback:** revert this change and the family registration together. An older core has no `RegisterAdapter`, so the family package does not compile against it.
- **Downstream:** `chainlink-ccip-solana` adds `pkg/cctp` and the blank import. The paired PR holds that change.
- **Config:** no config key changes. The adapter comes from the binary, not from the app config.

## References

- Paired PR: `chainlink-ccip-solana` — register the Solana CCTP adapter.
- Prior changelog entry this builds on: `2026-04-14_accessor_registry.md`.
- Related TODO: `verifier/pkg/token/cctp/attestation.go:177` (pinned `554fc9ab0bec`).
