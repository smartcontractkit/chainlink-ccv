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

# Configuration

The bootstrap config is a TOML file provided by the **node operator** and mounted into the
container (default path: `/etc/config.toml`, overridable via `BOOTSTRAPPER_CONFIG_PATH`). It
carries settings that are **operator- and environment-specific** — database credentials, keystore
password, JD connection details — and settings that are **common across all CCIP apps** but depend
on the operator's infrastructure, such as which chains the node has a signing identity on.

This file is **not shipped by Chainlink Labs**. It is the operator's responsibility to provide it.
The app-level configuration (job spec, aggregator addresses, chain selectors, etc.) is delivered
separately by JD after the node connects.

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
