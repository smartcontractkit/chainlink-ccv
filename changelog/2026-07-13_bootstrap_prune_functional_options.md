# Bootstrap: prune `With*` functional options in favor of config

## Summary

The bootstrapper's `With*` functional options are being pared back to a single principle:
**operator/environment tuning lives in the bootstrap config; source-level options are reserved for
the app's cryptographic identity (`WithKey`)**.

As a result, the two log-level options are removed (they were no-ops), the two path options are
unexported (they were only ever a test seam), and the deprecated default signing-key set is removed.
`WithKey` is unchanged.

---

## Breaking change: `WithLogLevel` and `WithLogLevelFromEnv` are removed

Both options wrote an internal field that nothing read — the effective log level has always come
from `[Monitoring].LogLevel` in the bootstrap config. They were no-ops, so **removing them changes
no runtime behavior**; only the call sites stop compiling.

**Migration:** delete the call. Set the level in your bootstrap `config.toml`:

```toml
[Monitoring]
LogLevel = "info"
```

Before:
```go
bootstrap.Run("MyApp", &factory{},
    bootstrap.WithLogLevelFromEnv(zapcore.InfoLevel),
    bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256),
)
```

After:
```go
bootstrap.Run("MyApp", &factory{},
    bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256),
)
```

---

## Breaking change: the default signing-key set is removed

Previously, calling `NewBootstrapper`/`Run` with **no** `WithKey` options initialized a default set
of three keys (CSA, ECDSA signing, EdDSA signing). That fallback is gone:

- Apps must now declare every signing key they need explicitly via `WithKey`.
- The EdDSA default key was used by no one and is simply dropped.
- The **CSA key is still auto-injected** when no CSA-purpose key is declared — every JD app needs it
  and it is harmless.

**Who is affected:** any app that relied on the default ECDSA signing key
(`bootstrap_default_ecdsa_signing_key` = `commit.DefaultECDSASigningKeyName`) without declaring it.
In practice this is the **Canton committee verifier**, which reuses the shared committee-verifier
factory. It signed correctly only because the default key name coincided with the constant the
factory signs with.

**Migration:** declare the key explicitly, matching the EVM committee verifier:

```go
bootstrap.Run("CantonCommitteeVerifier", cmd.NewCommitteeVerifierServiceFactory(),
    bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256),
)
```

> ⚠️ This is a **silent** break: without the explicit `WithKey`, the signing key is never created and
> signing fails at runtime rather than at compile time. Add the declaration when you bump the
> bootstrap dependency.

---

## Internal: `WithBootstrapperConfigPath` / `WithBootstrapperSecretsPath` unexported

These options were only ever called from the package's own tests (a parallel-safe, construction-time
path-injection seam). No production or downstream caller used them. They are now
`withBootstrapperConfigPath` / `withBootstrapperSecretsPath`. Production callers select these paths
via `BOOTSTRAPPER_CONFIG_PATH` / `BOOTSTRAPPER_SECRETS_PATH` (or the defaults), which is unchanged.
</content>
