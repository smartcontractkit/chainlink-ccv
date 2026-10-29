# Chain-neutral signer identity and signature paths

## Executive Summary

- Adds public-key-first keystore construction and exact-match validation against either the uncompressed
  public key or its derived EVM address.
- Adds R/S-only signing and encoding APIs so the generic verifier does not construct an Ethereum address.
- Existing address-returning APIs remain as EVM compatibility wrappers, and the 64-byte `R || S` wire
  format is unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `commit.ValidateSignerIdentity` | added | `ValidateSignerIdentity\(` | `verifier/pkg/commit/signer.go:34` | [#public-key-validation](#public-key-validation) |
| `commit.ResolveSignerIdentity` | added | `ResolveSignerIdentity\(` | `verifier/pkg/commit/signer.go:50` | [#public-key-validation](#public-key-validation) |
| `commit.NewECDSASignerFromKeystore` | added | `NewECDSASignerFromKeystore\(` | `verifier/pkg/commit/signer.go:218` | [#public-key-validation](#public-key-validation) |
| `commit.EVMAddressFromPublicKey` | added | `EVMAddressFromPublicKey\(` | `verifier/pkg/commit/signer.go:240` | [#public-key-validation](#public-key-validation) |
| `protocol.SignV27RS` and related R/S APIs | added | `SignV27RS\(|SignV27WithKeystoreSignerRS\(|EncodeSingleECDSASignatureRS\(` | `protocol/signature.go:104` | [#chain-neutral-signing](#chain-neutral-signing) |
| Standalone verifier signer validation | behavior-changed | `ResolveSignerIdentity\(` | `cmd/verifier/servicefactory.go:345` | [#public-key-validation](#public-key-validation) |

## Breaking Changes

*No breaking changes.* Existing validation, signing, encoding, and node-hosted constructor APIs retain
their signatures and behavior.

## Public-key validation

- **Before:** the standalone verifier discarded the keystore public key during validation and compared
  `signer_address` only with the derived Ethereum address. A 65-byte Canton public key therefore failed.
- **After:** `NewECDSASignerFromKeystore` returns the signer and SEC1 uncompressed public key without
  deriving a chain-specific identity. `ResolveSignerIdentity` returns an exact public-key match directly;
  only a different-length configuration triggers `EVMAddressFromPublicKey` for address comparison.
- Validation uses raw byte equality with no chain-family conditional or truncation. Empty, malformed, and
  mismatched values still fail startup; `"auto"` adopts the public key without EVM derivation.

## Chain-neutral signing

- **Before:** every verifier signing operation recovered an Ethereum address and populated `Data.Signer`,
  although single-signature encoding emitted only R and S.
- **After:** the verifier uses `SignV27RS`, `SignV27WithKeystoreSignerRS`, and
  `EncodeSingleECDSASignatureRS`. These paths perform the same V27 normalization and signature checks
  without deriving an address.
- Existing `SignV27`, `SignV27WithKeystoreSigner`, and `EncodeSingleECDSASignature` callers retain their
  behavior through compatibility wrappers. Aggregate EVM sorting and recovery are unchanged.

## Compatibility & Requirements

- **EVM:** existing 20-byte addresses continue to validate and signatures remain byte-for-byte compatible.
- **Canton:** the standalone verifier accepts the 65-byte SEC1 uncompressed public key, with or without
  a `0x` prefix, and signs without requiring an Ethereum address.
- **Node-hosted verifier:** unchanged; it continues to use `ValidateSignerAddress`.
- **Rollout:** no configuration or downstream API migration is required.

## References

- Prior changelog entry: `2026-10-29_length_agnostic_signer_address.md`
