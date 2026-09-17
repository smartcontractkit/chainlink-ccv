# Injectable CCTP chain codecs

## Executive Summary

- This change makes the chain accessor supply the CCTP codec for its chain. The codec gives the domain lookup, the transaction-hash codec, and the address codec.
- Before this change the CCTP verifier held chain knowledge in the core package. A static `Domains` map in the core package mapped a chain selector to a Circle domain. Two functions branched on the chain family to pick base58 for Solana and hex for EVM.
- The verifier already resolves one accessor per source chain through `chainaccess`. The accessor is now also the codec for that chain, so the runtime holds one chain-specific interface, not two.
- Affected code: `verifier/pkg/token/cctp`, `cmd/verifier/tokenfactory.go`, and `integration/pkg/accessors/evm`.
- Headline impact: this is a breaking change. `cctp.NewAttestationService` gained a required argument, and a source chain whose accessor does not implement `CCTPCodec` now fails at `Fetch`.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cctp.encodeTxHash` | removed | `\bencodeTxHash\b` | `verifier/pkg/token/cctp/attestation.go` | [#chain-codecs-moved-out-of-the-core-package](#chain-codecs-moved-out-of-the-core-package) |
| `cctp.decodeAddress` | removed | `\bdecodeAddress\b` | `verifier/pkg/token/cctp/attestation.go` | [#chain-codecs-moved-out-of-the-core-package](#chain-codecs-moved-out-of-the-core-package) |
| `cctp.NewAttestationService` | signature-changed | `NewAttestationService\(` | `verifier/pkg/token/cctp/attestation.go:71` | [#newattestationservice-takes-the-chain-codecs](#newattestationservice-takes-the-chain-codecs) |
| `chainaccess.Accessor.CCTPCodec` | signature-changed | `CCTPCodec\(\) \(CCTPCodec, error\)` | `pkg/chainaccess/interfaces.go:125` | [#the-accessor-exposes-the-codec](#the-accessor-exposes-the-codec) |
| `cctp.HTTPAttestationService.Fetch` | behavior-changed | `func \(h \*HTTPAttestationService\) Fetch` | `verifier/pkg/token/cctp/attestation.go:94` | [#fetch-reads-the-codec-map](#fetch-reads-the-codec-map) |
| `cctp.Domains` | removed | `cctp\.Domains\b` | `verifier/pkg/token/cctp/consts.go` | [#the-circle-domain-catalog-moved-to-the-evm-accessor](#the-circle-domain-catalog-moved-to-the-evm-accessor) |
| `evmaccessor.CCTPDomain` | added | `\bCCTPDomain\b` | `integration/pkg/accessors/evm/cctp_domains.go:63` | [#the-circle-domain-catalog-moved-to-the-evm-accessor](#the-circle-domain-catalog-moved-to-the-evm-accessor) |
| `chainaccess.CCTPCodec` | added | `\bCCTPCodec\b` | `pkg/chainaccess/interfaces.go:102` | [#the-accessor-exposes-the-codec](#the-accessor-exposes-the-codec) |
| `evmaccessor.Domain` | added | `func \(a \*accessor\) Domain` | `integration/pkg/accessors/evm/cctp_codec.go:18` | [#implement-the-codec-on-the-chain-accessor](#implement-the-codec-on-the-chain-accessor) |
| `evmaccessor.EncodeTxHash` | added | `func \(a \*accessor\) EncodeTxHash` | `integration/pkg/accessors/evm/cctp_codec.go:24` | [#implement-the-codec-on-the-chain-accessor](#implement-the-codec-on-the-chain-accessor) |
| `evmaccessor.DecodeAddress` | added | `func \(a \*accessor\) DecodeAddress` | `integration/pkg/accessors/evm/cctp_codec.go:29` | [#implement-the-codec-on-the-chain-accessor](#implement-the-codec-on-the-chain-accessor) |

## Breaking Changes

### The accessor exposes the codec

- **What changed:** `chainaccess.CCTPCodec` is a new interface, and `chainaccess.Accessor` gained `CCTPCodec() (CCTPCodec, error)`.
- **Before:** the runtime held one chain-specific interface, `Accessor`. The CCTP core package held the CCTP chain facts in a second place.
- **After:** the codec lives on the accessor, next to `SourceReader()`. The runtime still holds one chain-specific interface.
- **Why:** one chain-specific contract per family. A chain repository implements the codec on the accessor that it already registers through `chainaccess.Register`.
- **Who is affected:** every implementation of `chainaccess.Accessor`. An implementation without a codec returns an error from the getter, which is the convention for the other optional capabilities.

### NewAttestationService takes the chain codecs

- **What changed:** `cctp.NewAttestationService(lggr, monitoring, config)` became `cctp.NewAttestationService(lggr, monitoring, config, cctpCodecs)`.
- **Before:** the service resolved a codec from the source chain family on every call.
- **After:** the caller passes `map[protocol.ChainSelector]chainaccess.CCTPCodec`. The service reads the map.
- **Why:** the runtime already resolves one accessor per source chain. The codec comes from that accessor, so the core package needs no family dispatch and no registry of its own.
- **Who is affected:** every caller of `cctp.NewAttestationService`. In this repository that is `cmd/verifier/tokenfactory.go`.

### A source chain accessor must implement CCTPCodec

- **What changed:** `Fetch` looks up `h.cctpCodecs[message.SourceChainSelector]`.
- **Before:** the core package held the domain lookup and both codecs, so every family worked with no extra method.
- **After:** an accessor whose `CCTPCodec()` returns an error is absent from the map, and `Fetch` returns `no CCTP chain codec for source chain selector`. The error occurs at `Fetch`, not at startup.
- **Why:** a chain family owns its CCTP facts. The chain repository implements them on its own accessor.
- **Who is affected:** a binary that verifies CCTP for a chain whose accessor lacks the three methods. The EVM accessor in `integration/pkg/accessors/evm` implements them. The Solana accessor in `chainlink-ccip-solana/pkg/accessors` implements them.

### Chain codecs moved out of the core package

- **What changed:** `encodeTxHash` and `decodeAddress` are gone from the core package.
- **Before:** each function called `chainsel.GetSelectorFamily` and branched to base58 or hex.
- **After:** the codec is a method on the chain accessor. `codec.EncodeTxHash` and `codec.DecodeAddress` replace the two functions.
- **Why:** the core path must not branch on a chain family. This change also resolves the codec TODO that the earlier registry work left open.
- **Who is affected:** no consumer. Both functions were unexported.

### Fetch reads the codec map

- **What changed:** `Fetch` reads the codec from `cctpCodecs`, then calls `codec.Domain(message.SourceChainSelector)` and `codec.EncodeTxHash(txHash)`.
- **Before:** `Fetch` read `Domains[uint64(message.SourceChainSelector)]` and called `encodeTxHash`.
- **After:** the same data comes from the codec. Two error strings are new or changed: `no CCTP chain codec for source chain selector` and `unsupported source chain selector`.
- **Why:** the core path must not resolve a codec from a chain family.
- **Who is affected:** a consumer that matches on the old error string `unsupported source chain selector`. That string still exists for a codec whose domain table has no entry for the selector.

### The Circle domain catalog moved to the EVM accessor

- **What changed:** `cctp.Domains` is gone. The EVM catalog lives in `integration/pkg/accessors/evm/cctp_domains.go`, and `evmaccessor.CCTPDomain(selector)` reads it.
- **Before:** the CCTP core package held the catalog, so `verifier/pkg/token/cctp` carried EVM chain data.
- **After:** `verifier/pkg/token/cctp/consts.go` holds only the verifier version constants. The EVM accessor owns the EVM catalog and the Solana accessor owns the Solana table.
- **Why:** the CCTP core must hold no chain data of any family, so the EVM chain repository can own its table later. `build/devenv` already imports the EVM accessor, so its call sites keep working.
- **Who is affected:** a consumer that imported `cctp.Domains`. Use `evmaccessor.CCTPDomain` for an EVM selector, or the family accessor's `CCTPCodec.Domain` for any family.

## Migration Guide

Every chain family follows the same path: the accessor implements the contract. The EVM accessor already does, so the EVM-only token verifier needs no change and is the standard case.

Another family implements the three methods on its accessor and returns the accessor from `CCTPCodec()`. No registration and no blank import are needed, because `chainaccess` already resolves that accessor for each source chain.

1. Add `Domain`, `EncodeTxHash`, and `DecodeAddress` to the family accessor type.
2. Keep the family domain table in the family repository.
3. Return the accessor from `CCTPCodec()`, and confirm the accessor type satisfies `chainaccess.CCTPCodec` with a compile-time assertion.

```go
// After — the family accessor type
var _ chainaccess.CCTPCodec = (*accessor)(nil)

func (a *accessor) CCTPCodec() (chainaccess.CCTPCodec, error) {
	return a, nil
}
```

`cmd/verifier/tokenfactory.go` reads `accessor.CCTPCodec()` for each accessor it already resolves, and collects the results into the map that it passes to `NewAttestationService`.

## Implement the codec on the chain accessor

`pkg/chainaccess/interfaces.go` holds the contract, and `Accessor` exposes it through `CCTPCodec()`. No registry and no lookup function exist.

```go
// CCTPCodec holds the chain-specific CCTP knowledge the verifier needs: the Circle
// domain for a chain selector, and the wire codecs for a transaction hash and an address.
type CCTPCodec interface {
	Domain(selector protocol.ChainSelector) (uint32, bool)
	EncodeTxHash(txHash protocol.ByteSlice) string
	DecodeAddress(address string) (protocol.UnknownAddress, error)
}
```

The EVM implementation is `integration/pkg/accessors/evm/cctp_codec.go`. It reads the EVM catalog through `CCTPDomain`, returns the hex transaction hash, and decodes a hex address. A compile-time assertion ties it to the EVM accessor type.

## New Features / Additions

- **`chainaccess.CCTPCodec`** — the chain-family contract, in `pkg/chainaccess/interfaces.go`. `Accessor.CCTPCodec()` exposes it.
- **EVM accessor codec** — `integration/pkg/accessors/evm/cctp_codec.go` with `Domain`, `EncodeTxHash`, and `DecodeAddress`.
- **`cctpCodecs` map** — built in `cmd/verifier/tokenfactory.go` from the accessors the runtime already resolves.

## Compatibility & Requirements

- **Rollout:** ship the family accessor codec and this core change together. A family accessor without the three methods fails every CCTP attestation for that chain.
- **Rollback:** revert this change and the family accessor methods together. An older core has no `cctpCodecs` argument, so a caller does not compile against it.
- **Downstream:** `chainlink-ccip-solana` adds the three methods and the getter to its Solana accessor. The paired PR holds that change.
- **Config:** no config key changes. The codec comes from the accessor, not from the app config.

## References

- Paired PR: `chainlink-ccip-solana` — implement the Solana CCTP codec on the Solana accessor.
- Prior changelog entry this builds on: `2026-04-14_accessor_registry.md`.
