# Verifier credentials move to a verifier secrets file (backwards-compatible)

## Summary

The committee and token verifiers can now read their sensitive configuration —
the application storage DB URL (`CL_DATABASE_URL`) and, for the committee
verifier, the per-aggregator HMAC credentials (`VERIFIER_AGGREGATOR_*`) — from a
verifier **secrets file** instead of environment variables. The env vars still
work unchanged (the file is optional), and when a value is set in both the file
and the environment, the **file wins**. This is the verifier's own secrets file,
distinct from the bootstrap `secrets.toml`: `CL_DATABASE_URL` is a
different database than the bootstrap `[db]`.

---

## New: verifier secrets file via per-app `*_SECRETS_PATH`

Each verifier app resolves its own path env var, falling back to a namespaced
default. The service factory loads the file at startup (so each chain-family
binary's `main.go` stays boilerplate-free); the `ccv` admin CLI loads it too.

| App | Env var | Default path |
|-----|---------|--------------|
| Committee verifier | `COMMITTEE_VERIFIER_SECRETS_PATH` | `/etc/committee-verifier/secrets.toml` |
| Token verifier | `TOKEN_VERIFIER_SECRETS_PATH` | `/etc/token-verifier/secrets.toml` |

```toml
# secrets.toml
[db]
url = "postgres://user:pass@host:5432/verifier?sslmode=disable"

# Committee verifier only. secret_name joins to the app config's
# [[aggregators]].secret_name; omit secret_name for the legacy single-aggregator
# default (matches the un-suffixed VERIFIER_AGGREGATOR_API_KEY / _SECRET_KEY).
[[aggregators]]
secret_name = "arbitrum_mainnet"
api_key     = "..."
secret_key  = "..."
```

An absent file is never an error (env-only, the backwards-compatible path). A
**present** file is validated strictly: malformed TOML, unknown/misspelled keys,
duplicate `secret_name`s, or more than one omitted-`secret_name` entry fail
startup loudly.

---

## Breaking change (internal API): read sites take the parsed secrets

Callers that constructed these directly must pass the loaded secrets. Apps that
only deploy the binaries are unaffected — this is a Go API change.

| Symbol | Before | After |
|--------|--------|-------|
| `verifier.ConnectToPostgresDB` | `(lggr)` | `(lggr, *vsecrets.VerifierSecrets)` |
| `commit.AggregatorConnection.ResolveHMACConfig` | `()` | `(vsecrets.AggregatorSecrets)` |
| `verifier.RunCCVCLI` | `(args)` | `(args, secretsEnvVar, defaultSecretsPath)` |

`NewCommitteeVerifierServiceFactory()` is unchanged — the factory loads the
secrets in `Start` itself. The env var name constant `DatabaseURLEnvVar` moved
from `cmd/verifier` to the new leaf package `verifier/pkg/vsecrets`.

---

## Breaking change: `CL_DATABASE_*` pool-tuning env vars removed

`CL_DATABASE_MAX_OPEN_CONNS`, `CL_DATABASE_MAX_IDLE_CONNS`,
`CL_DATABASE_CONN_MAX_LIFETIME`, and `CL_DATABASE_CONN_MAX_IDLE_TIME` are no
longer read. They were set by no deployment and always fell back to defaults, so
the defaults (`20` / `10` / `300s` / `60s`) are now fixed constants. Only the
credential-bearing `CL_DATABASE_URL` moved to the secrets file. Pool tuning can
be reintroduced via config if a deployment ever needs it.

---

## Migration

Env-var configuration is deprecated but fully supported. To cut over: add the
secrets file (file wins), verify the app picks it up, then remove
`CL_DATABASE_URL` / `VERIFIER_AGGREGATOR_*` from the deployment. No deprecation
warning is emitted yet.

---

## Recommended additions

- Update deployment manifests (Helm/k8s) to mount the verifier `secrets.toml`
  from a Secret at the app's default path (or set `*_SECRETS_PATH`).
