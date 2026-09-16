# Injectable CCTP chain codecs

## Executive Summary

- This change makes each chain family supply its own CCTP codec. The codec gives the domain lookup, the transaction-hash codec, and the address codec.
- Before this change the CCTP verifier held chain knowledge in the core package. A static `Domains` map mapped a chain selector to a Circle domain. Two functions branched on the chain family to pick base58 for Solana and hex for EVM.
- Affected code: `verifier/pkg/token/cctp`. Affected consumers: every binary that verifies CCTP for a non-EVM source chain. `chainlink-ccip-solana` is one example.
- Headline impact: this is a breaking behavior change. A CCTP source chain of a family that has no registered codec now fails at `Fetch`. The EVM-only token verifier is not affected.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cctp.encodeTxHash` | removed | `\bencodeTxHash\b` | `verifier/pkg/token/cctp/attestation.go:191` | [#chain-codecs-moved-out-of-the-core-package](#chain-codecs-moved-out-of-the-core-package) |
| `cctp.decodeAddress` | removed | `\bdecodeAddress\b` | `verifier/pkg/token/cctp/attestation.go:205` | [#chain-codecs-moved-out-of-the-core-package](#chain-codecs-moved-out-of-the-core-package) |
| `cctp.HTTPAttestationService.Fetch` | behavior-changed | `NewAttestationService\(` | `verifier/pkg/token/cctp/attestation.go:90` | [#fetch-resolves-the-codec](#fetch-resolves-the-codec) |
| `cctp.Domains` | behavior-changed | `cctp\.Domains\b` | `verifier/pkg/token/cctp/consts.go:21` | [#domains-is-the-evm-catalog-only](#domains-is-the-evm-catalog-only) |
| `cctp.ChainCodec` | added | `\bChainCodec\b` | `verifier/pkg/token/cctp/codec.go:19` | [#register-a-family-codec](#register-a-family-codec) |
| `cctp.RegisterChainCodec` | added | `\bRegisterChainCodec\b` | `verifier/pkg/token/cctp/codec.go:33` | [#register-a-family-codec](#register-a-family-codec) |
| `cctp.ChainCodecFor` | added | `\bChainCodecFor\b` | `verifier/pkg/token/cctp/codec.go:44` | [#register-a-family-codec](#register-a-family-codec) |

## Breaking Changes

### A source chain family must register a CCTP codec

- **What changed:** `HTTPAttestationService.Fetch` and `cctpMatchesMessage` resolve the chain codec through `ChainCodecFor(sourceChainSelector)`. The core package no longer branches on the chain family.
- **Before:** the core package held the domain lookup and both codecs. EVM and Solana sources worked with no registration.
- **After:** `Fetch` returns an error for a source chain family that has no registered codec. The error occurs at `Fetch`, not at startup.
- **Why:** a chain family owns its CCTP facts. A family adds a codec without a change in the core package.
- **Who is affected:** a binary that verifies CCTP for a non-EVM source chain and does not register a codec. In practice this is the Solana CCTP token verifier. The EVM-only token verifier is not affected. ccv registers the EVM codec from the package `init()`.

### Chain codecs moved out of the core package

- **What changed:** `encodeTxHash` and `decodeAddress` are gone from the core package.
- **Before:** each function called `chainsel.GetSelectorFamily` and branched to base58 or hex.
- **After:** the codec is a method on the registered `ChainCodec`. `codec.EncodeTxHash` and `codec.DecodeAddress` replace the two functions.
- **Why:** the `TODO` at `verifier/pkg/token/cctp/attestation.go:177` asked for a per-family codec.
- **Who is affected:** no consumer. Both functions were unexported.

### Fetch resolves the codec

- **What changed:** `Fetch` resolves the codec for `message.SourceChainSelector`. It then calls `codec.Domain(message.SourceChainSelector)` and `codec.EncodeTxHash(txHash)`.
- **Before:** `Fetch` read `Domains[uint64(message.SourceChainSelector)]` and called `encodeTxHash`.
- **After:** the same data comes from the codec. The error message changes for an unknown selector.
- **Why:** the core path must not hold a chain-specific branch.
- **Who is affected:** a consumer that matches on the old error string `unsupported source chain selector`.

### Domains is the EVM catalog only

- **What changed:** `cctp.Domains` stays exported, but the two Solana entries are gone. The EVM codec reads the map.
- **Before:** `Domains` held every family. It listed `SOLANA_MAINNET` to domain 5 and `SOLANA_DEVNET` to domain 5.
- **After:** `Domains` holds only EVM entries. The Solana codec holds the Solana domain table.
- **Why:** a chain repository owns its chain data. `build/devenv` and tooling keep using `Domains` for EVM selectors.
- **Who is affected:** a consumer that reads `Domains` for a Solana selector. The key is now absent. Read the Solana codec in `chainlink-ccip-solana/pkg/cctp` instead.

## Migration Guide

Do nothing for an EVM-only token verifier.

For a non-EVM family, do these steps. The example is Solana.

1. Implement `cctp.ChainCodec` in the family repository.
2. Register the implementation from a package `init()`.
3. Blank-import the package that holds the `init()` in the token verifier `main.go`.

```go
// After — pkg/cctp/codec.go in the family repository
func init() {
	ccvcctp.RegisterChainCodec(chainsel.FamilySolana, solanaCodec{})
}
```

```go
// After — cmd/tokenverifier/main.go in the family repository
import (
	_ "github.com/smartcontractkit/chainlink-ccip-solana/pkg/accessors" // solana accessor driver
	_ "github.com/smartcontractkit/chainlink-ccip-solana/pkg/cctp"      // solana CCTP codec
)
```

`chainlink-ccip-solana` does these steps in `pkg/cctp/codec.go` and `cmd/tokenverifier/main.go`.

## Register a family codec

`verifier/pkg/token/cctp/codec.go` holds the contract and the registry.

```go
// ChainCodec holds the chain-specific CCTP facts for one chain family.
type ChainCodec interface {
	Domain(selector protocol.ChainSelector) (uint32, bool)
	EncodeTxHash(txHash protocol.ByteSlice) string
	DecodeAddress(address string) (protocol.UnknownAddress, error)
}
```

`RegisterChainCodec` stores one codec per `chainsel` family name. It panics on a nil codec and on a duplicate registration. The package resolves the codec for a selector through `chainsel.GetSelectorFamily` in `ChainCodecFor`.

The EVM codec is `verifier/pkg/token/cctp/codec_evm.go`. It registers `chainsel.FamilyEVM` from `init()`, and it reads the `Domains` catalog.

## New Features / Additions

- **`cctp.ChainCodec`** — the chain-family contract. See `verifier/pkg/token/cctp/codec.go`.
- **`cctp.RegisterChainCodec`** — family registration. Call it from a package `init()`.
- **EVM codec** — `verifier/pkg/token/cctp/codec_evm.go`.

## Compatibility & Requirements

- **Rollout:** ship the family binary with the family codec before the core change reaches the family. A binary without a codec fails every CCTP attestation for that family.
- **Rollback:** revert this change and the family registration together. An older core has no `RegisterChainCodec`, so the family package does not compile against it.
- **Downstream:** `chainlink-ccip-solana` adds `pkg/cctp` and the blank import. The paired PR holds that change.
- **Config:** no config key changes. The codec comes from the binary, not from the app config.

## References

- Paired PR: `chainlink-ccip-solana` — register the Solana CCTP codec.
- Prior changelog entry this builds on: `2026-04-14_accessor_registry.md`.
- Related TODO: `verifier/pkg/token/cctp/attestation.go:177` (pinned `554fc9ab0bec`).
