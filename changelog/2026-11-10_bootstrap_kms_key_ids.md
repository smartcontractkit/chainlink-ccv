# Bootstrap KMS: per-key KMS keys via `key_ids`

## Executive Summary

- Adds an optional `[keystore.kms.key_ids]` table mapping a key name to its KMS key, overriding the per-type default (`ecdsa_key_id` / `ed25519_key_id`).
- Lets a service declare several `WithKey` keys of the same type on the KMS backend; previously they collided on the single per-type key.
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
provider     = "aws"
ecdsa_key_id = "<default-ecdsa-key-id>"

[keystore.kms.key_ids]
"evm/tx/transmitter"    = "<evm-key-id>"
"solana/tx/transmitter" = "<solana-key-id>"
```

Each declared key resolves from its `key_ids` entry, else the default for its type. Startup fails if an entry is empty or names no declared key, or if two keys resolve to the same KMS key.

## verifyKeys

Still fails startup on any inaccessible key, but joins one error per key so a single deploy surfaces every bad key.

## Compatibility & Requirements

- **Rollback:** an older binary rejects a config containing `key_ids` as an unknown key; remove the table first.
