# Bootstrap config split into non-secret config + secrets files

## Summary

The bootstrapper's operator config can now be split by sensitivity into a
non-secret `config.toml` and a `secrets.toml` (credentials only), so the two
halves can be deployed from separate sources (e.g. a k8s ConfigMap vs a Secret).
The legacy monolithic single-file layout still works unchanged.

---

## Breaking change: `bootstrap.Config` is now composed of two embedded structs

The credential-bearing sections moved into a `Secrets` struct and the rest into
`NonSecretConfig`; `Config` embeds both. Field **reads** are unaffected
(`cfg.JD`, `cfg.DB` still work via promotion), but **keyed composite literals no
longer compile**. TOML decoding/encoding is unchanged — sections stay top-level.

| What | Before | After |
|------|--------|-------|
| `Config` shape | flat: `JD`, `Keystore`, `DB`, `Server`, `Chains`, `Monitoring` | `struct { NonSecretConfig; Secrets }` |
| Secret sections | `Keystore`, `DB` on `Config` | on `Secrets` (`[keystore]`, `[db]`) |
| Non-secret sections | `JD`, `Server`, `Chains`, `Monitoring` on `Config` | on `NonSecretConfig` |

Before:
```go
cfg := bootstrap.Config{JD: jd, Keystore: ks, DB: db, Server: srv}
```

After:
```go
cfg := bootstrap.Config{
    NonSecretConfig: bootstrap.NonSecretConfig{JD: jd, Server: srv},
    Secrets:         bootstrap.Secrets{Keystore: ks, DB: db},
}
```

---

## Breaking change: `LoadAndValidateConfig` takes a path list

Now accepts an ordered list of files, decoded into one struct (later files
overlay earlier ones), so config + secrets merge before validation.

Before:
```go
err := bootstrap.LoadAndValidateConfig(path, cfg, needsInfra)
```

After:
```go
err := bootstrap.LoadAndValidateConfig([]string{configPath, secretsPath}, cfg, needsInfra)
```

---

## New: separate secrets file via `BOOTSTRAPPER_SECRETS_PATH`

In JD mode the bootstrapper loads `config.toml` (`BOOTSTRAPPER_CONFIG_PATH`,
default `/etc/config.toml`) and overlays an optional `secrets.toml`
(`BOOTSTRAPPER_SECRETS_PATH`, default `/etc/bootstrap/secrets.toml`) carrying
`[keystore]` and `[db]`. The secrets file wins for any section it defines and is
optional — if absent, a monolithic `config.toml` with all sections still loads.
Static-TOML mode (token verifier) is unchanged. Set the path explicitly with the
new `WithBootstrapperSecretsPath` option.

```toml
# /etc/config.toml (non-secret)
[jd]
server_wsrpc_url = "ws://jd:8080/ws"
server_csa_public_key = "..."
[server]
listen_port = 9988

# /etc/bootstrap/secrets.toml (secrets)
[keystore]
password = "..."
[db]
url = "postgres://user:pass@host:5432/db"
```

Migration: the monolithic layout is deprecated and will be removed once
deployments cut over. No deprecation warning is emitted yet.

---

## Recommended additions

- Update deployment manifests (Helm/k8s) to mount `secrets.toml` from a Secret
  and `config.toml` from a ConfigMap before the monolith is removed.
