# Executor devenv migration to JD-only lifecycle

## Summary

Standalone executors in the devenv now always run under the JD lifecycle
(`bootstrap.Run` without TOML config). The old "standalone-no-JD" path and its
supporting code have been removed. `ImplFactory` no longer has a
`SupportsBootstrapExecutor` method; all families use the same launch path.

---

## Breaking change: `ImplFactory.SupportsBootstrapExecutor()` removed

The method was used to route EVM executors to the old standalone-no-JD path.
All executors now use the JD path unconditionally.

| What | Before | After |
|------|--------|-------|
| `ImplFactory` interface | `SupportsBootstrapExecutor() bool` present | method removed |
| `evmImplFactory` | returned `false` | method removed |
| Devenv routing | two launch paths (`launchStandaloneExecutors` / `launchBootstrappedExecutors`) | single `launchExecutors` |

**If you implement `ImplFactory` in a product repo**, remove the
`SupportsBootstrapExecutor()` method.

---

## Breaking change: `executorsvc.NewStandalone` removed

The function that started an executor container without a DB or JD connection no
longer exists. Use `executorsvc.New` instead.

Before:
```go
out, err := executorsvc.NewStandalone(exec, blockchainOutputs)
```

After:
```go
out, err := executorsvc.New(exec, blockchainOutputs, jdInfra)
```

---

## Breaking change: `Input.GeneratedConfig` and `GenerateConfigWithBlockchainInfos` removed

These fields and methods supported the old TOML-config-only path.

| Removed | Replacement |
|---------|-------------|
| `Input.GeneratedConfig string` | not needed; job spec is the config source |
| `Input.GenerateConfigWithBlockchainInfos(...)` | not needed |
| `DefaultExecutorDBName` constant | DB name defaults to `ContainerName + "-db"` |

---

## Breaking change: `services/executor.go` deleted

The top-level `build/devenv/services/executor.go` file (package `services`) has
been removed. It duplicated executor container logic that now lives in
`build/devenv/services/executor/base.go` (package `executorsvc`).

If you imported types from `services.ExecutorInput`, `services.NewExecutor`, or
`services.ApplyExecutorDefaults`, migrate to the equivalents in
`build/devenv/services/executor/`.

---

## Breaking change: `env.toml` executor entries require a `[executor.db]` block

Standalone executors now always need a Postgres sidecar. Add a `[executor.db]`
sub-table to each `[[executor]]` entry in your environment TOML.

Before:
```toml
[[executor]]
  container_name = "my-executor"
  port = 8101
```

After:
```toml
[[executor]]
  container_name = "my-executor"
  [executor.db]
    image = "postgres:16-alpine"
    name = "my-executor-db"
```

Two port fields have been removed:

- **`port` on `[[executor]]`** — removed entirely. The executor no longer exposes an
  HTTP port; it registers with JD over WSRPC.
- **`port` on `[executor.db]`** — removed entirely. The database port is allocated
  internally by Docker and is not user-configurable. The `DefaultExecutorDBPort`
  constant has also been removed.

---

## Breaking change: executor application config path removed from standalone binary

The standalone executor binary previously accepted a path to its chain/application
config TOML via a CLI argument or `$EXECUTOR_CONFIG_PATH`. That config (chains,
transmitter keys, etc.) is now delivered by JD as a job spec, so the argument is
gone.

The **bootstrap layer** config (Postgres URL, JD connection, keystore password,
HTTP port) is still a TOML file. Its path is resolved by:

1. `$BOOTSTRAPPER_CONFIG_PATH` environment variable
2. Default: `/etc/config.toml`

Before:
```sh
# bootstrap config:  /etc/config.toml (or $BOOTSTRAPPER_CONFIG_PATH)
# application config: explicit path
executor /path/to/executor-app-config.toml
# or
EXECUTOR_CONFIG_PATH=/path/to/executor-app-config.toml executor
```

After:
```sh
# bootstrap config:  /etc/config.toml (or $BOOTSTRAPPER_CONFIG_PATH) — unchanged
# application config: delivered via JD job spec — no CLI arg needed
executor
```

Bootstrap config shape (unchanged):
```toml
[jd]
server_wsrpc_url    = "ws://jd-host:8080/ws"
server_csa_public_key = "<hex ed25519 pubkey>"

[keystore]
password = "..."

[db]
url = "postgres://user:pass@host:5432/executor"

[server]
listen_port = 9988
```

---

## Bug fix: DB name collision in devenv

`ApplyDefaults` previously hardcoded the DB container name to `"executor-db"`
for all executors, causing collisions when multiple executors ran on the same
host. The default is now `ContainerName + "-db"` (e.g. `"default-executor-1-db"`).
