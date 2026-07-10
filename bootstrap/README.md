# Bootstrap package

The `bootstrap` package is the common runtime foundation for all CCIP standalone applications
(committee verifier, executor, etc.). It handles the operational concerns that every app shares,
leaving each app free to focus on its domain logic:

- Initialising and managing the encrypted keystore (generating keys on first boot, unlocking on
  restart).
- Connecting to the Job Distributor (JD) and managing the full job lifecycle: receiving proposals,
  approving jobs, handling replacements and deletions, and recovering from crashes.
- Publishing the node's onchain signing keys to JD on connect so that deployment tooling can read
  them back via `ListNodeChainConfigs`.
- Exposing an HTTP info server for health checks and key inspection.

Apps plug in via the `ServiceFactory` interface. The bootstrapper calls `Start` when a job spec
arrives from JD and `Stop` when the job is deleted or replaced.

# Lifecycle modes

The bootstrapper runs in one of two modes, selected by the top-level `app_config_mode` key in the
bootstrap `config.toml` (not an env var or flag — so switching modes is a config change, not an
image rebuild):

- `app_config_mode = "jd_app_config"` (the default when the key is omitted): load the app config from
  a Job Distributor over WSRPC and run the full job lifecycle. Requires the `[jd]`, `[db]`,
  `[keystore]`, and `[server]` config sections.
- `app_config_mode = "local_app_config"`: run without JD. The bootstrapper reads the app config from
  the file at `local_app_config_path` instead of receiving it from JD. If the config also carries
  `[db]`+`[keystore]`, it initializes a Postgres-backed keystore so the service can sign (and starts
  the info server when `[server]` is set); a service that needs no keystore (the token verifier)
  omits them. This is the mode for the CCV starter kit and local testing where JD is not available.

```toml
# JD mode (or just omit app_config_mode)
app_config_mode = "jd_app_config"

[jd]
server_wsrpc_url = "ws://jd.example.com:8080/ws"
# ... plus [db], [keystore], [server]
```

```toml
# Local mode
app_config_mode = "local_app_config"
local_app_config_path = "/etc/myapp/app-config.toml"

# [db] + [keystore] here too if the service signs (committee verifier, executor); omit for the token verifier
```

## One image, two launch modes

The mode lives in config, so the **same service image** (`verifier:latest` for the committee
verifier, `executor:latest` for the executor) runs either way — only the mounted config differs. No
rebuild or env change needed to switch.

JD mode (default):

```sh
docker run \
  -v ./bootstrap-config.toml:/etc/config.toml \      # app_config_mode="jd_app_config", [jd]+[db]+[keystore]+[server]
  -v ./bootstrap-secrets.toml:/etc/bootstrap/secrets.toml \  # optional split-out [db]/[keystore]
  verifier:latest
# app config (aggregators, addresses, ...) arrives from JD after connect
```

Local mode (no JD):

```sh
docker run \
  -v ./bootstrap-config.toml:/etc/config.toml \      # app_config_mode="local_app_config", local_app_config_path=..., [db]+[keystore]
  -v ./app-config.toml:/etc/myapp/app-config.toml \  # the app config, formerly shipped by JD
  verifier:latest
```

Notes:
- Local mode removes the JD dependency, not the database: a signing service (committee verifier,
  executor) still needs Postgres for its keystore, and the `[db]`/`[keystore]` sections must be
  present for the keystore to initialize. It is not a zero-infra mode.
- The bootstrap config path (`BOOTSTRAPPER_CONFIG_PATH`, default `/etc/config.toml`) and
  `local_app_config_path` are distinct files: the former holds the operator/infra config plus the
  mode selection, the latter holds the app's own config.
- The app config must be present at `local_app_config_path` when the container starts; the
  bootstrapper reads it and starts the service synchronously (a missing file is an immediate error).
  This is the normal operator flow: write the config, then start the service. Where the signing
  address is needed to configure on-chain contracts before the config (which depends on those
  contracts) is known — as in devenv's no-JD mode — the orchestrator provisions the node's keystore up
  front (see `SeedKeys`) so it learns the address without running the service, then starts the
  container once the config is ready. The bootstrapper itself does no waiting or polling.

# Configuration

The bootstrap config is a TOML file provided by the **node operator** and mounted into the
container (default path: `/etc/config.toml`, overridable via `BOOTSTRAPPER_CONFIG_PATH`). It
carries settings that are **operator- and environment-specific** — database credentials, keystore
password, JD connection details — and settings that are **common across all CCIP apps** but depend
on the operator's infrastructure, such as which chains the node has a signing identity on.

This file is **not shipped by Chainlink Labs**. It is the operator's responsibility to provide it.
The app-level configuration (aggregator addresses, chain selectors, etc.) is delivered separately —
by JD after the node connects in `jd` mode, or from the local app-config file in `local` mode (see
Lifecycle modes above).

```toml
[jd]
# WebSocket RPC endpoint of the Job Distributor.
server_wsrpc_url = "ws://jd.example.com:8080/ws"
# Ed25519 CSA public key of the JD server (hex-encoded, 32 bytes).
server_csa_public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[keystore]
# Password used to encrypt the keystore at rest. Use high-entropy values in production.
password = "change-me"

[db]
# Postgres URL for the bootstrap database (separate from any app database, but may share a server).
url = "postgres://user:pass@localhost:5432/bootstrap_db?sslmode=disable"

[server]
# Port for the HTTP info server (health checks, key inspection).
listen_port = 9988

[monitoring]
# Optional. Operator-provided OTel exporter config. When absent the app falls back to its own
# deprecated monitoring field (if any). See pkg/monitoring for the full schema.
# [monitoring.beholder]
# otel_exporter_http_endpoint = "collector.example.com:4318"

[[chains]]
# Declare each chain on which this node has a signing identity. The bootstrapper derives the
# onchain signing address from the node's ECDSA_S256 key and registers it with JD on connect,
# making it available to deployment tooling via ListNodeChainConfigs.
# One entry per chain; multiple [[chains]] blocks are allowed.
type = "EVM"   # chain family — EVM, SOLANA, APTOS, STELLAR, CANTON, STARKNET, TRON, TON, SUI
id   = "1"     # chain ID (e.g. EVM chain ID, Solana cluster name)
```

# Requirements

The bootstrapper requires a dedicated Postgres database. It stores:

- The encrypted keystore (private keys locked under the `[keystore].password`).
- The current job spec and proposal status (used for crash recovery and replacement rollback).

This must be a **separate** database from any app-level database to keep migrations isolated.

# Usage example

```go
// serviceFactory implements bootstrap.ServiceFactory.
type serviceFactory struct{}

func (s *serviceFactory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
    var cfg myapp.Config
    if err := spec.GetAppConfig(&cfg); err != nil {
        return err
    }
    // start your app using cfg, deps.Keystore, deps.Registry, deps.Monitoring ...
    return nil
}

func (s *serviceFactory) Stop(ctx context.Context) error {
    // stop your app ...
    return nil
}

func main() {
    if err := bootstrap.Run(
        "MyApp",
        &serviceFactory{},
        bootstrap.WithLogLevelFromEnv(zapcore.InfoLevel),
        // Declare every key the app needs. The bootstrapper creates them on first boot.
        bootstrap.WithKey("my-signing-key", "signing", keystore.ECDSA_S256),
    ); err != nil {
        panic(err)
    }
}
```

See `cmd/verifier/committee/main.go` for a complete real-world example.
