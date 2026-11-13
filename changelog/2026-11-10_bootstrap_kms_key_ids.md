# Bootstrap KMS: per-key KMS keys via `key_ids`

## Executive Summary

- Adds a `[keystore.kms.key_ids]` table mapping each declared key name to its KMS key.
- Lets a service declare several `WithKey` keys of the same type on the KMS backend; previously they collided on the single per-type key.
- Deprecates `ecdsa_key_id` and `ed25519_key_id`; they cannot be combined with `key_ids`.
- `verifyKeys` now reports every inaccessible KMS key in one error instead of the first.
- No breaking changes: without `key_ids`, resolution is unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `bootstrap.KMSKeystoreConfig.KeyIDs` | added | `\bKeyIDs\b` | `bootstrap/config.go:78` | [#key_ids](#key_ids) |
| `bootstrap.buildKMSNameMap` | behavior-changed | `buildKMSNameMap\(` | `bootstrap/bootstrap.go:975` | [#key_ids](#key_ids) |
| `keys.KMSKeystore.verifyKeys` | behavior-changed | `verifyKeys\(` | `bootstrap/keys/kms.go:91` | [#verifykeys](#verifykeys) |

## Breaking Changes

*No breaking changes.*

## key_ids

```toml
[keystore.kms]
provider = "aws"

[keystore.kms.key_ids]
"evm/tx/transmitter"      = "<evm-key-id>"
"solana/tx/transmitter"   = "<solana-key-id>"
bootstrap_default_csa_key = "<csa-key-id>"
```

Every declared key needs an entry, and every entry must name a declared key. The CSA key is provisioned only when `bootstrap_default_csa_key` is mapped; JD mode requires it. Startup fails if an entry is empty or two keys resolve to the same KMS key.

## verifyKeys

Still fails startup on any inaccessible key, but joins one error per key so a single deploy surfaces every bad key.

## Compatibility & Requirements

- **Rollback:** an older binary rejects a config containing `key_ids` as an unknown key; remove the table first.
