# Length-agnostic `signer_address` validation

## Executive Summary

- `commit.ValidateSignerAddress` no longer requires a `0x` prefix and no longer requires a 20-byte
  (`common.AddressLength`) value: it compares the decoded configured bytes against the keystore's
  bytes and nothing else.
- Previously a non-EVM verifier (Canton) failed to boot with `invalid signer_address "...": hex string
  without 0x prefix`, because it pins the 65-byte uncompressed public key instead of an EVM address.
- Affects `verifier/pkg/commit` and every caller of `ValidateSignerAddress`; EVM deployments behave
  exactly as before.
- No breaking changes: every value rejected before is still rejected, except well-formed hex that only
  differed by prefix or length and genuinely matches the keystore key.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `commit.ValidateSignerAddress` | behavior-changed | `ValidateSignerAddress\(` | `verifier/pkg/commit/signer.go:31` | [#length-agnostic-validation](#length-agnostic-validation) |

## Breaking Changes

*No breaking changes.* The signature is unchanged.

## Length-agnostic validation

- **What changed:** the configured value is decoded with `hex.DecodeString(strings.TrimPrefix(configured, "0x"))`
  and compared to the keystore key with `protocol.UnknownAddress.Equal`. The explicit `0x` requirement
  and the `len(decoded) != common.AddressLength` check are gone.
- **Before:** `hexutil.Decode(configured)` rejected unprefixed hex, and the decoded value had to be
  exactly 20 bytes; longer keys were then truncated through `common.BytesToAddress`.
- **After:** any even-length hex is accepted, with or without `0x`, of any byte length — 20-byte EVM
  addresses and 65-byte Canton public keys both work. Equality is raw byte equality, so a value that
  only shares its trailing 20 bytes with the keystore key does not match. Empty and non-hex values
  still fail with `invalid signer_address`, and `"auto"` still opts out via `commit.AutoSignerAddress`.
- **Why:** the check asserts "the keystore holds the key this job pins", not "this is an EVM address";
  the 20-byte assumption is EVM-specific and broke the Canton committee verifier's rollout.
- **Who is affected:** Canton (and any future non-EVM) verifiers pinning a public key in
  `signer_address`. EVM verifiers keep the same accept/reject outcome for 20-byte `0x`-prefixed values.

```toml
# Canton committee verifier: unprefixed 65-byte public key, now accepted
signer_address = "04b3c1…6f7e"
```

## Compatibility & Requirements

- **Rollout:** none. `signer_address` is a string in the job spec schema; EVM specs need no change.
- **Rollback:** a binary swap; the previous binary keeps rejecting non-20-byte values.

## References

- Prior changelog entries this builds on: `2026-09-02_optional_signer_address.md`,
  `2026-08-11_cutover_parity_cleanup.md`
