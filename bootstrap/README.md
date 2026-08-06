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
  the file at `local_app_config_path` instead of receiving it from JD. If the config also carries a
  keystore (`[db]`+`[keystore].password`, or `[keystore].backend = "kms"`), it initializes one so the
  service can sign (and starts the info server when `[server]` is set); a service that needs no
  keystore (the token verifier) omits them. This is the mode for the CCV starter kit and local
  testing where JD is not available.

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
  executor) on the default postgres backend still needs Postgres for its keystore, and the
  `[db]`/`[keystore]` sections must be present for the keystore to initialize. It is not a
  zero-infra mode. The exception is the KMS backend (`[keystore].backend = "kms"`), which needs
  no database in local mode.
- The bootstrap config path (`BOOTSTRAPPER_CONFIG_PATH`, default `/etc/config.toml`) and
  `local_app_config_path` are distinct files: the former holds the operator/infra config plus the
  mode selection, the latter holds the app's own config.
- The app config may be delivered after the container starts. If `local_app_config_path` does not
  exist yet at startup (and the service has a keystore + `[server]` info server), the bootstrapper
  comes up serving its signing keys and health endpoint and waits for the file to appear, then starts
  the service — mirroring how JD delivers the app config after the node connects. This lets an
  orchestrator read the node's signing address (needed to configure on-chain contracts) before the
  config, which depends on those contracts, is known. Mount `local_app_config_path` inside a mounted
  **directory** and write the file atomically (temp + rename) so the waiting bootstrapper never reads
  a partial file. When the file is already present at startup, the service starts immediately.

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

## Keystore backends

The `[keystore].backend` key selects where private keys live:

- `postgres` (default): keys are generated on first boot and stored encrypted under
  `[keystore].password` in the bootstrap Postgres database. Requires `[db].url` and
  `[keystore].password`.
- `kms`: keys live in AWS KMS and private key material never leaves KMS; the bootstrapper holds
  only IAM credentials. Configure one KMS Key ID per declared key under `[keystore.kms]`
  (`ecdsa_key_id`, `ed25519_key_id`). No database or password is needed for the keystore itself
  (JD mode still needs `[db]` for the job store).

The Ed25519 requirement is mode-driven, not backend-driven. The Ed25519 CSA key authenticates the
node to JD, so it is mandatory in JD mode — with KMS that means `ed25519_key_id` is required. In
local mode there is no JD and the CSA key only backs Beholder telemetry auth, so it is optional:
the postgres backend still generates one for free, while the KMS backend uses one only when
`ed25519_key_id` is explicitly set (KMS keys cannot be created by the service). Omit it to run a
local-mode KMS deployment with no Ed25519 key at all; Beholder then sends telemetry without auth
headers.

| Mode  | Backend  | CSA (Ed25519) key         | `ed25519_key_id` |
|-------|----------|---------------------------|------------------|
| JD    | postgres | auto-injected (required)  | n/a              |
| JD    | kms      | auto-injected (required)  | required         |
| local | postgres | auto-injected (Beholder)  | n/a              |
| local | kms      | only if configured        | optional         |

## Adopting a key from a Chainlink node

A node operator moving off CL mode has a key that must survive the move: the onchain signing key
registered in the `CommitteeVerifier` signer set. `[key_import]` adopts one exported from a Chainlink
node instead of generating it.

```toml
[key_import]
# The key file exported from the Chainlink node.
path          = "/etc/ccv/migration/key.json"
# The password it was exported under, in its own file so this config carries no credentials.
password_path = "/etc/ccv/migration/export-password.txt"
# Required: the address the export must carry. The process refuses to boot on a mismatch —
# this is the check that catches a wrong node's export mounted by mistake.
expected_id   = "0x1234...abcd"
```

The `ccv migrate` commands in the verifier image produce all of this: `ccv migrate export` exports
the signing key from the node, verifies it, and writes this block with `expected_id` already filled
in; `ccv migrate inspect` prints the identity a mounted file carries, to confirm the right file
before boot.

Two paths and a check. The section names neither the keystore key nor the export format: an
application declares exactly one key it can import into, so the target is unambiguous, and the
format is read from the file (an OCR2 bundle declares its chain type, an eth key carries an
address).

The import runs only when the key is absent, so it is a no-op on every restart after the first and
the exported files can be unmounted once the node has come up once.

The CSA key is never imported. It authenticates the node to JD and has no on-chain meaning, so a
migration repoints the existing JD node record at the standalone node's own CSA key via
`UpdateNodeRequest.public_key` rather than copying a private key across. See
`docs/migration/evm-cl-to-standalone.md` for the full procedure.

# Requirements

The bootstrapper requires a dedicated Postgres database. It stores:

- The encrypted keystore (private keys locked under the `[keystore].password`).
- The current job spec and proposal status (used for crash recovery and replacement rollback).
- Chain state that accessors need across a restart, in a schema per chain family. Today that is
  `evm.heads` (see Chain accessor persistence below).

This must be a **separate** database from any app-level database to keep migrations isolated.

## Chain accessor persistence

Chain accessors receive the bootstrap database through `chainaccess.Deps` and use it for state that
has to survive a restart. Each family owns a schema, so the tables can keep the names the upstream
ORMs query without colliding with the bootstrapper's own. Migrations live in `bootstrap/db/migrations`
and run on connect, so there is one ordered migration set and one version table for the database.

Only the EVM accessor persists anything. It runs chainlink-evm's production head tracker, which keeps
a chain of recent heads; the Solana and Canton accessors read head and finality state from their RPC
on every call and hold no durable state.

Persistence is optional and follows the `[db]` section:

- With `[db].url` set, the EVM head tracker writes to `evm.heads` and reloads on startup, so a
  restart resumes from the heads it already had instead of refetching them.
- Without it, the accessor runs the same tracker against an in-memory saver, which is the behavior
  before this existed. The process logs a warning at startup so this is not silent. Local mode with
  no database and the KMS keystore backend both land here.

If `[db].url` is set but the database is unreachable or unmigrated, startup fails with an error
naming `evm.heads` rather than coming up and quietly running unpersisted.

Heads are written one row per block per chain and trimmed below `HistoryDepth` under the finalized
block, so the table stays proportional to that depth rather than growing with uptime. Nothing needs
pruning by hand.

### What is not persisted

Transaction state is not. The standalone accessor runs chainlink-evm's TXM v2, which holds
transactions, attempts, and receipts in memory; chainlink-evm ships no durable store for it.

This is safe for the cases that matter, because TXM v2 reconciles against the chain rather than a
database. It reads the pending nonce per address on start, so a restart cannot reuse a nonce.
Duplicate delivery is prevented by the executor reading each message's on-chain execution state
before executing and by the OffRamp itself, not by transaction state. Confirmed executions are
rediscovered by the destination reader's backfill.

What a restart does lose is the driver behind a transaction that reached the mempool but was not yet
mined: nothing rebroadcasts or gas bumps it, and transactions from the same address cannot confirm
until it does. It resolves without intervention once that transaction is mined or evicted, but a
transaction stuck through a gas spike can hold up an address for a while. The accessor counts these
at startup, from the gap between the address's pending and latest nonce, and logs a warning naming
the address and count. That warning is worth an alert.

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
        // Declare every key the app needs. The bootstrapper creates them on first boot.
        // A CSA key for JD auth is injected automatically if you don't declare one and the
        // mode/backend combination calls for one (see Keystore backends above).
        bootstrap.WithKey("my-signing-key", "signing", keystore.ECDSA_S256),
    ); err != nil {
        panic(err)
    }
}
```

See `cmd/verifier/committee/main.go` for a complete real-world example.
