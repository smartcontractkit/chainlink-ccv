# Bootstrap app-config source is config-driven (`app_config_mode`)

## Summary

The bootstrapper now selects how it loads application config from the bootstrap
`config.toml` rather than from environment variables or compile-time options.
A new top-level key, `app_config_mode`, chooses between fetching the app config
from a Job Distributor (`jd_app_config`, the default) and reading it from a local
file (`local_app_config`). This lets the same service image run either way with
only a config change — no rebuild, no env var — and unblocks the no-JD path (CCV
starter kit, local testing) where a Job Distributor is not available.

---

## New: `app_config_mode` in the bootstrap config

```toml
# JD mode (default when app_config_mode is omitted — existing deployments unchanged)
app_config_mode = "jd_app_config"

[jd]
server_wsrpc_url = "ws://jd.example.com:8080/ws"
server_csa_public_key = "..."
# plus [db], [keystore], [server]
```

```toml
# Local mode: read the app config from a file instead of JD
app_config_mode = "local_app_config"
local_app_config_path = "/etc/myapp/app-config.toml"

# [db] + [keystore] here too if the service signs (committee verifier, executor);
# omit them for a keystore-less service (token verifier). When present, the
# Postgres-backed keystore is initialized; when absent, the service runs keystore-less.
```

- `jd_app_config` (default): unchanged behavior — load the app config from JD and
  run the full job lifecycle. Requires `[jd]`, `[db]`, `[keystore]`, `[server]`.
- `local_app_config`: read the app config from `local_app_config_path` (required),
  no JD. The keystore is initialized only when both `[db].url` and
  `[keystore].password` are set.

An unknown `app_config_mode` value fails startup with a clear error.

The mode env var and the `WithJD` / `WithTOMLAppConfig` / mode-related functional
options were removed; only `BOOTSTRAPPER_CONFIG_PATH` and
`BOOTSTRAPPER_SECRETS_PATH` remain as env inputs.

---

## Breaking change: token verifier deployments must set `app_config_mode`

The token verifier previously loaded its app config directly from
`TOKEN_VERIFIER_CONFIG_PATH` (default `/etc/config.toml`) via a compile-time
option. It is now config-driven like every other service: it reads the bootstrap
config at `BOOTSTRAPPER_CONFIG_PATH` and follows `app_config_mode`.

`TOKEN_VERIFIER_CONFIG_PATH` is **no longer read.** A token verifier deployment
must be updated so its bootstrap config declares local mode and points at the app
config file:

```toml
# /etc/config.toml (BOOTSTRAPPER_CONFIG_PATH)
app_config_mode       = "local_app_config"
local_app_config_path = "/etc/token-verifier/app-config.toml"
# [monitoring] as needed; no [jd]/[db]/[keystore] (the token verifier signs nothing)
```

with the token app config mounted at `local_app_config_path`. Without this, the
missing `app_config_mode` defaults to `jd_app_config` and the token verifier will
try to start a JD lifecycle and fail. (`devenv` is already updated.)

Committee verifier and executor deployments that use JD are **unaffected**: an
absent `app_config_mode` defaults to JD.
