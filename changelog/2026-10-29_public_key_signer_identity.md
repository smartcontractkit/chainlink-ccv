# Chain-neutral signer identity

## Executive Summary

- Adds public-key-first keystore construction so the standalone verifier does not derive an EVM address
  before it knows which identity encoding the job pins.
- Resolves `signer_address` against the public key using the key-or-address matching introduced by the
  hotfix, including 33-byte compressed and 65-byte uncompressed SEC1 keys.
- Keeps signing and encoding on the existing protocol APIs, without adding parallel R/S-only variants.
- The 64-byte `R || S` wire format and existing address-returning compatibility APIs are unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `commit.ResolveSignerIdentity` | added | `ResolveSignerIdentity\(` | `verifier/pkg/commit/signer.go:34` | [#public-key-validation](#public-key-validation) |
| `commit.NewECDSASignerFromKeystore` | added | `NewECDSASignerFromKeystore\(` | `verifier/pkg/commit/signer.go` | [#public-key-validation](#public-key-validation) |
| `commit.EVMAddressFromPublicKey` | added | `EVMAddressFromPublicKey\(` | `verifier/pkg/commit/signer.go` | [#public-key-validation](#public-key-validation) |
| `commit.normalizeAndEncodeSignature` | added | `normalizeAndEncodeSignature\(` | `verifier/pkg/commit/signer.go` | [#chain-neutral-signing](#chain-neutral-signing) |
| Standalone verifier signer validation | behavior-changed | `ResolveSignerIdentity\(` | `cmd/verifier/servicefactory.go` | [#public-key-validation](#public-key-validation) |

## Breaking Changes

*No breaking changes.* Existing validation, signing, encoding, and node-hosted constructor APIs retain
their signatures and behavior. No new public protocol signing APIs are introduced.

## Public-key validation

- **Hotfix baseline:** the standalone verifier validates the keystore public key and accepts either an
  EVM address or SEC1 public key when both describe the same key.
- **Permanent change:** `NewECDSASignerFromKeystore` returns the signer and its public key without
  unconditionally deriving an EVM address. `ResolveSignerIdentity` returns the configured identity after
  applying the same strict key matching, so downstream logging retains the job's identity encoding.
- Exact public-key matches use raw byte equality without chain-specific derivation. Different encodings
  are compared through their derived EVM addresses; truncation and trailing-byte matches are not allowed.
- Empty, malformed, and mismatched values still fail startup. `"auto"` adopts the public key.

## Chain-neutral signing

The verifier signs with the private key or keystore, applies `protocol.NormalizeToV27`, verifies that the
normalized signature recovers a public key, and calls the existing `protocol.EncodeSingleECDSASignature`.
It no longer derives an Ethereum address merely to discard it during single-signature encoding. The
existing EVM signing and aggregation APIs remain available unchanged for callers that need addresses.

## Compatibility & Requirements

- **EVM:** existing 20-byte addresses continue to validate and signatures remain byte-for-byte compatible.
- **Canton:** the standalone verifier accepts SEC1 public keys with or without a `0x` prefix and signs
  without requiring an Ethereum address.
- **Node-hosted verifier:** unchanged; it continues to use `ValidateSignerAddress`.
- **Rollout:** no configuration or downstream API migration is required.

## References

- Hotfix: `fix(verifier): match signer_address by key or address` (#1564).
- Prior changelog entry: `2026-10-29_length_agnostic_signer_address.md`.
