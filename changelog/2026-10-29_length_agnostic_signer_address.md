# Key-or-address `signer_address` validation

## Executive Summary

- `commit.ValidateSignerAddress` now accepts a `signer_address` in any of the encodings a verifier key
  is published in: `0x`-prefixed or bare hex, a 20-byte EVM address, or a SEC1 public key (65-byte
  uncompressed / 33-byte compressed).
- The keystore side may likewise be either an address or a public key: values that differ in encoding
  are reduced to the EVM address derived from the key before comparing.
- Previously a Canton verifier failed to boot twice over: first on the missing `0x` prefix and the
  20-byte length requirement, then on comparing a 65-byte configured public key against the 20-byte
  address the caller passed in.
- Affects `verifier/pkg/commit` and every caller of `ValidateSignerAddress`, plus the standalone
  verifier's startup path, which now validates the keystore's public key instead of its address.
- No breaking changes: the signature is unchanged and EVM deployments keep their exact behavior.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `commit.ValidateSignerAddress` | behavior-changed | `ValidateSignerAddress\(` | `verifier/pkg/commit/signer.go:31` | [#key-or-address-validation](#key-or-address-validation) |
| `commit.keysMatch` | added | `\bkeysMatch\(` | `verifier/pkg/commit/signer.go:57` | [#key-or-address-validation](#key-or-address-validation) |
| `commit.addressForKey` | added | `\baddressForKey\(` | `verifier/pkg/commit/signer.go:72` | [#key-or-address-validation](#key-or-address-validation) |

## Breaking Changes

*No breaking changes.* `ValidateSignerAddress(configured string, actual protocol.UnknownAddress) error`
keeps its signature and its accept/reject contract, except for values that describe the same key in a
different encoding (they are now accepted) and the removal of the 20-byte requirement.

## Key-or-address validation

- **What changed:** the configured value is decoded with `hex.DecodeString(strings.TrimPrefix(configured, "0x"))`
  with no length requirement. It is compared to `actual` in two steps: byte equality first; if that
  fails, both sides are reduced to their EVM address (`commit.addressForKey` — identity for a 20-byte
  address, `crypto.PubkeyToAddress` for a 33- or 65-byte SEC1 public key) and compared again.
- **Before:** `hexutil.Decode` rejected unprefixed hex; the value had to be exactly 20 bytes; longer
  values were truncated through `common.BytesToAddress`; and the standalone verifier passed the
  keystore-derived address, so a job pinning the public key could never match.
- **After:** any even-length hex is accepted, and a job pinning either encoding matches a keystore
  holding either encoding. Derivation is keccak-based, never truncation, so a key cannot match on
  shared trailing bytes. Empty and non-hex values still fail with `invalid signer_address`, `"auto"`
  still opts out via `commit.AutoSignerAddress`, and a genuine mismatch still fails with
  `signing key does not match signer_address` (previously "signing address does not match …").
- **Why:** the check asserts "the keystore holds the key this job pins", not "this is an EVM address".
  EVM pins a 20-byte address, Canton pins the 65-byte public key, and the two encodings must agree.
- **Who is affected:** Canton (and any future non-EVM) verifiers pinning a public key in
  `signer_address`. EVM verifiers keep the same accept/reject outcome for 20-byte `0x`-prefixed values.

Caller change in `cmd/verifier/servicefactory.go`: the standalone verifier now validates
`NewSignerFromKeystore`'s returned public key (`signer, signingPubKey, signerAddress, err := ...`)
rather than `signerAddress`, so non-EVM pins compare the raw key. `signerAddress` is still what gets
passed to `commit.NewCommitVerifier` and logged as `Using signer address`.

```toml
# Canton committee verifier: unprefixed 65-byte public key
signer_address = "042aee…9bb92"   # matches keystore address 0x96a6c9…cc581
# EVM verifier: unchanged
signer_address = "0x96a6c9439db276d168ac9f9287deccec63acc581"
```

## Compatibility & Requirements

- **Rollout:** none. `signer_address` is a string in the job spec schema; EVM specs need no change.
  Out-of-tree verifiers call `ValidateSignerAddress` unchanged, whether they pass an address or a key.
- **Rollback:** a binary swap; the previous binary rejects any `signer_address` that is not 20 bytes.

## References

- Prior changelog entries this builds on: `2026-09-02_optional_signer_address.md`,
  `2026-08-11_cutover_parity_cleanup.md`
