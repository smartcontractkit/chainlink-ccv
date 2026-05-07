# Declarative key initialization via `WithKey`

## Summary

Services now declare exactly which keys they require at startup using `bootstrap.WithKey` options,
rather than the bootstrapper unconditionally provisioning a fixed three-key set. Callers that pass
no `WithKey` options get the original defaults unchanged.

---

## New: `bootstrap.WithKey`

Pass one option per required key. Each key is created on first run if absent.

```go
bootstrap.Run(
    "MyService",
    myFactory,
    bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256),
)
```

The **CSA key is provisioned automatically** in JD mode — callers do not need to declare it.
The bootstrapper injects `bootstrap.DefaultCSAKeyName` (Ed25519) unless the caller has already
declared a key with purpose `"csa"` via `WithKey`.

Services that pass **no** `WithKey` options continue to receive the original default set
(CSA + ECDSA + EdDSA), so existing binaries that have not been updated are unaffected.

---

## Breaking change: executor provisions `default_evm_key`, not `DefaultECDSASigningKeyName`

The standalone executor binary now explicitly declares its key set. The ECDSA signing key name
changed from the shared default to an executor-specific name, and the EdDSA key is no longer
provisioned at all.

| Key | Before (implicit default) | After (explicit) |
|-----|--------------------------|-----------------|
| CSA | `DefaultCSAKeyName` | `DefaultCSAKeyName` (unchanged) |
| ECDSA signing | `DefaultECDSASigningKeyName` | `"default_evm_key"` |
| EdDSA signing | `DefaultEdDSASigningKeyName` | *(not provisioned)* |

**Existing executor nodes** retain any keys already in the database. Only fresh nodes are
affected — they will provision `default_evm_key` instead of `DefaultECDSASigningKeyName`.

---

## Breaking change: `BootstrapKeys.EdDSAPublicKey` removed (devenv)

The `EdDSAPublicKey` field has been removed from `services.BootstrapKeys` in the devenv package.
It was fetched from the bootstrap info-server but never consumed anywhere. Code that reads
`.EdDSAPublicKey` will not compile and should be deleted.

---

## Breaking change: `GetBootstrapKeys` returns 2 keys, not 3 (devenv)

`services.GetBootstrapKeys` now requests only CSA + ECDSA from the bootstrap info-server.
The hardcoded `len != 3` assertion has been replaced with a check against the number of keys
requested.

A new `services.GetExecutorBootstrapKeys` function requests only the CSA key and is used by
the executor devenv setup path.

Before:
```go
keys, err := services.GetBootstrapKeys(bootstrapURL) // requested 3 keys
_ = keys.EdDSAPublicKey                              // now removed
```

After:
```go
// For executors (CSA only):
keys, err := services.GetExecutorBootstrapKeys(bootstrapURL)

// For verifiers (CSA + ECDSA):
keys, err := services.GetBootstrapKeys(bootstrapURL)
```

---

## Breaking change: key name constants moved to canonical packages

The constants previously exported from `bootstrap/keys` are now private. Each key name is
exported from the package that owns the key.

| Constant | Old location | New location |
|----------|-------------|--------------|
| `DefaultCSAKeyName` | `bootstrap/keys` | `bootstrap` |
| `DefaultECDSASigningKeyName` | `bootstrap/keys` | `verifier/pkg/commit` |

Update import sites:

```go
// Before
import bskeys "github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
bootstrap.WithKey(bskeys.DefaultCSAKeyName,          "csa",     keystore.Ed25519)
bootstrap.WithKey(bskeys.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256)

// After
import (
    "github.com/smartcontractkit/chainlink-ccv/bootstrap"
    "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
)
// CSA key is auto-provisioned; only declare signing keys explicitly:
bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256)
```

`bootstrap/keys` retains its utility functions (`EnsureKey`, `NewCSASigner`, `NewPGStorage`,
`DecodeEd25519PublicKey`) — only the constants are no longer exported.
