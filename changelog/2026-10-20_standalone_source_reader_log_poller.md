# Standalone verifier reads EVM source chains through its own LogPoller

## Executive Summary

- The standalone committee verifier can now read `CCIPMessageSent` logs through a LogPoller it runs itself. Before this, only the CL-mode verifier did (`2026-10-07_source_reader_log_poller.md`). It is off by default. You turn it on per chain with `log_poller_source_reader_enabled = true` in the EVM config, and it needs `[db].url` in a new EVM secrets file.
- The EVM accessor owns its own database: the `evm` schema (LogPoller tables plus `evm.lease_lock`), migrated with its own goose version table (`evm_goose_db_version`). It connects and migrates lazily, the first time a LogPoller reader is built. It holds a node-style database lease (new `common/dblease`), so only one process writes the LogPoller tables at a time.
- The LogPoller reader now reports its own finality violations (`chainaccess.FinalityViolationReporter`) and its own health (new optional `chainaccess.SourceHealthReporter`). `evm.NewLogPollerFinality` is removed. The chain health gauge now comes from one function, `sourcereader.Service.chainHealth`.
- The startup load now does three new things. It takes the lease before it writes. It waits until the checkpoint is finalized. If the replay hits a finality violation, it stops retrying and blocks reads.
- New commands: `verifier ccv blocks find-lca` and `verifier ccv blocks remove-blocks`, which mirror the node's commands. The finality-violation runbook now covers both the node and the standalone verifier.
- Breaking for integrators: `evm.NewLogPollerFinality` is removed, the EVM accessor builds its `SourceReader` lazily (so construction errors now surface on the first `SourceReader()` call), and `RunCCVCLI` gains a trailing variadic. The rest of the change is additive.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewLogPollerFinality` | removed | `\bNewLogPollerFinality\(` | — | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `constructors.newLogPollerConfig` (unexported) | removed | `\bnewLogPollerConfig\(` | — | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `services.CreateBootstrapDBInitScript` (`build/devenv`) | removed | `\bCreateBootstrapDBInitScript\b` | — | [#devenv-and-ci](#devenv-and-ci) |
| `verifier.RunCCVCLI` (`cmd/verifier`) | signature-changed | `\bRunCCVCLI\(` | `cmd/verifier/run_ccv_cli.go:39` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| EVM `accessor.SourceReader` | behavior-changed | `\.SourceReader\(\)` | `integration/pkg/accessors/evm/factory.go:378` | [#lazy-source-reader-and-reader-selection](#lazy-source-reader-and-reader-selection) |
| EVM `accessor.Close` | behavior-changed | `accessor\)\.Close\(\|\.Close\(\)` | `integration/pkg/accessors/evm/factory.go:475` | [#evm-database-and-lease](#evm-database-and-lease) |
| `evm.CreateEVMAccessorFactory` | behavior-changed | `\bCreateEVMAccessorFactory\(` | `integration/pkg/accessors/evm/factory_constructor.go:40` | [#configuration](#configuration) |
| `evm.LogPollerSourceReader.LoadFrom` startup load | behavior-changed | `\.LoadFrom\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:162` | [#startup-load-changes](#startup-load-changes) |
| `evm.LogPollerSourceReader.Loaded` | behavior-changed | `\.Loaded\(\)` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:176` | [#startup-load-changes](#startup-load-changes) |
| `evm.LogPollerSourceReader.LatestAndFinalizedBlock` / `LatestSafeBlock` | behavior-changed | `\.(LatestAndFinalizedBlock\|LatestSafeBlock)\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:450` | [#startup-load-changes](#startup-load-changes) |
| `evm.LogPollerSourceReader.FetchMessageSentEvents` | behavior-changed | `\.FetchMessageSentEvents\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:373` | [#startup-load-changes](#startup-load-changes) |
| `sourcereader.Service.Ready` and chain health gauge | behavior-changed | `RecordChainHealthy\(` | `verifier/pkg/sourcereader/service.go:318` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `constructors.NewVerificationCoordinator` (CL mode) | behavior-changed | `constructors\.NewVerificationCoordinator\(` | `integration/pkg/constructors/committee_verifier.go:43` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| Committee verifier factory `Start` / `Stop` | behavior-changed | `NewCommitteeVerifierServiceFactory\(` | `cmd/verifier/servicefactory.go:134` | [#verifier-service-factory](#verifier-service-factory) |
| `testutil.NewTestDB` | behavior-changed | `testutil\.NewTestDB\(` | `verifier/testutil/test_db.go:24` | [#test-helpers](#test-helpers) |
| `chainaccess.SourceHealthReporter` | added | `\bSourceHealthReporter\b` | `pkg/chainaccess/interfaces.go:76` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `chainaccess.GenericConfig.VerifierID` | added | `GenericConfig\b` | `pkg/chainaccess/registry.go:70` | [#configuration](#configuration) |
| `verifier.WithSourceHealthReporters` | added | `\bWithSourceHealthReporters\(` | `verifier/pkg/coordinator.go:87` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `sourcereader.WithHealthReporter` | added | `\bWithHealthReporter\(` | `verifier/pkg/sourcereader/service.go:115` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `evm.LogPollerSourceReader.FinalityViolated` / `Healthy` | added | `\.(FinalityViolated\|Healthy)\(\)` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:146` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `evm.LogPollerConfig.Start` | added | `LogPollerConfig\{` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:67` | [#startup-load-changes](#startup-load-changes) |
| `evm.NewLogPollerConfig` | added | `\bNewLogPollerConfig\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:72` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `evm.CheckpointAboveFinalizedError` | added | `\bCheckpointAboveFinalizedError\b` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:45` | [#startup-load-changes](#startup-load-changes) |
| `evmconfig.ChainConfig.LogPollerSourceReaderEnabled` (`log_poller_source_reader_enabled`) | added | `log_poller_source_reader_enabled\|LogPollerSourceReaderEnabled` | `integration/pkg/accessors/evmconfig/config.go:56` | [#configuration](#configuration) |
| `evmconfig.Config.LogPollerSourceReaderChains` | added | `\bLogPollerSourceReaderChains\(` | `integration/pkg/accessors/evmconfig/config.go:60` | [#configuration](#configuration) |
| `evmconfig.Secrets`, `evmconfig.DBConfig`, `LoadSecretsFile`, `ResolveSecretsPath`, `EVMSecretsPathEnv`, `DefaultEVMSecretsPath` | added | `evmconfig\.(Secrets\|DBConfig\|LoadSecretsFile\|ResolveSecretsPath\|EVMSecretsPathEnv)\b\|EVM_SECRETS_PATH` | `integration/pkg/accessors/evmconfig/secrets.go:22` | [#configuration](#configuration) |
| `dblease.Lease`, `dblease.New`, `dblease.Config`, `dblease.DefaultConfig`, `dblease.ErrLeaseHeld` | added | `\bdblease\.` | `common/dblease/lease.go:54` | [#evm-database-and-lease](#evm-database-and-lease) |
| `evmdb.RunPostgresMigrationsContext`, `evmdb.NewLogPollerDB`, `evmdb.NewLease`, `evmdb.LeaseTable` | added | `accessors/evm/db"` | `integration/pkg/accessors/evm/db/run_migrations.go:25` | [#evm-database-and-lease](#evm-database-and-lease) |
| `migrations.PostgresMigrations` (`accessors/evm/migrations`) | added | `accessors/evm/migrations"` | `integration/pkg/accessors/evm/migrations/migrations.go:8` | [#evm-database-and-lease](#evm-database-and-lease) |
| `evm.OpenDB` | added | `\bevm\.OpenDB\(` | `integration/pkg/accessors/evm/database.go:65` | [#evm-database-and-lease](#evm-database-and-lease) |
| `evm.SelectorFromChainID`, `evm.CheckLogPollerSchema`, `evm.FindLCA`, `evm.RemoveBlocksFrom`, `evm.LCA` | added | `evm\.(SelectorFromChainID\|CheckLogPollerSchema\|FindLCA\|RemoveBlocksFrom)\(` | `integration/pkg/accessors/evm/evm_logpoller_operator.go:37` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| `blocks.Command`, `blocks.InitBlocksCommandsWithFactory`, `blocks.Operator`, `blocks.Deps`, `blocks.LCA` (`accessors/evm/cli/blocks`) | added | `evm/cli/blocks"` | `integration/pkg/accessors/evm/cli/blocks/operator.go:21` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| `testutil.NewTestDBWithURL` | added | `\bNewTestDBWithURL\(` | `verifier/testutil/test_db.go:32` | [#test-helpers](#test-helpers) |
| devenv `services.PostgresURL`, `services.CreateDBInitScriptFile`, `committeeverifier.InternalDBURL`, `committeeverifier.Input.ExtraDatabases`, `Output.ExtraDBConnectionStrings`, `chainreg.VerifierDatabases`, `Registry.ResolveVerifierDatabases`, `evm.VerifierDatabases`, `evm.LogPollerSourceReaderOn`, `evm.EVMDBName` | added | `\b(PostgresURL\|CreateDBInitScriptFile\|InternalDBURL\|ExtraDatabases\|ResolveVerifierDatabases\|VerifierDatabases\|LogPollerSourceReaderOn\|EVMDBName)\b` | `build/devenv/chainreg/registry.go:169` | [#devenv-and-ci](#devenv-and-ci) |

## Breaking Changes

### NewLogPollerFinality removed

- **What changed:** `evm.NewLogPollerFinality(lp)` and its `logPollerFinality` type are removed. `*evm.LogPollerSourceReader` now implements `chainaccess.FinalityViolationReporter` itself.
- **Before:** `finalityReporter = evm.NewLogPollerFinality(lp)`
- **After:** `finalityReporter, _ = sourceReader.(chainaccess.FinalityViolationReporter)`
- **Why:** The reader keeps the violation after the LogPoller clears its own flag (see [#startup-load-changes](#startup-load-changes)). A separate wrapper around the LogPoller would miss that.
- **Who is affected:** Anyone who built the finality reporter from the LogPoller. `constructors.NewVerificationCoordinator` is updated in this repo.

### EVM accessor builds its source reader lazily

- **What changed:** `GetAccessor` no longer constructs the RPC source reader. It keeps the `SourceReaderParams`, and the first `accessor.SourceReader()` call builds either the LogPoller reader or the RPC reader. Later calls return the same reader, or the same error.
- **Before:** A source-reader construction error failed `GetAccessor` and closed the runtime.
- **After:** `GetAccessor` succeeds, and `SourceReader()` returns `failed to create EVM source reader: ...`. An accessor with no on-ramp config still returns `source reader not available`.
- **Why:** If a chain selects the LogPoller reader, nothing should build the RPC reader. The LogPoller reader also needs the database, which connects only on first use.
- **Who is affected:** Callers that relied on `GetAccessor` to validate the source reader. `newAccessor` (tests) still accepts a prebuilt reader.

### RunCCVCLI trailing variadic

- **What changed:** `RunCCVCLI(args, secretsEnvVar, defaultSecretsPath string, commands ...func(logger.Logger) cli.Command)`.
- **Why:** The committee verifier binary adds `blocks.Command` under `ccv`. Building a command must do no I/O.
- **Who is affected:** Source-compatible for existing callers. Only the committee binary passes `blocks.Command`. The token verifier binary does not register `ccv blocks`.

## Migration Guide

1. Replace `evm.NewLogPollerFinality(lp)` with a type assertion on the reader:

   ```go
   // Before
   sourceReader, err = evm.NewLogPollerSourceReader(ctx, params, cfg)
   finalityReporter = evm.NewLogPollerFinality(lp)
   ```

   ```go
   // After
   sourceReader, err = evm.NewLogPollerSourceReader(ctx, params, evm.NewLogPollerConfig(lp, verifierID))
   finalityReporter, _ = sourceReader.(chainaccess.FinalityViolationReporter)
   ```
2. To feed the reader's health into `/health` and the chain gauge, also assert `chainaccess.SourceHealthReporter`, and pass it with `verifier.WithSourceHealthReporters(map[ChainSelector]SourceHealthReporter)`. Take both reporters *before* any instrumentation wrapper hides them. `cmd/verifier/servicefactory.go` shows how.
3. Handle construction errors from `accessor.SourceReader()`, not from `GetAccessor`.
4. To turn the standalone LogPoller on for a chain, set the chain's `log_poller_source_reader_enabled = true` in the EVM config, and mount an EVM secrets file with `[db].url` (see [#configuration](#configuration)). The committee verifier job spec must carry its top-level `verifier_id`. It already does.

## New Features / Additions

### Configuration

- **EVM config:** `[chains.<selector>] log_poller_source_reader_enabled = true` (default false). `evmconfig.Config.LogPollerSourceReaderChains()` returns the enabled selectors, sorted.
- **EVM secrets file (new):** `evmconfig.Secrets{DB *DBConfig}` at `EVM_SECRETS_PATH`, default `/etc/evm/secrets.toml`. The file is optional: `ResolveSecretsPath` returns `""` when it does not exist, and `LoadSecretsFile("")` returns empty `Secrets`. It is decoded strictly (unknown keys fail), and `[db]` requires `url`. Per AGENTS.md, the database URL has no environment variable. The generated reference is `docs/config/evm/secrets.documented.toml`.

  ```toml
  [db]
  url = "postgres://user:password@host:5432/evm_db?sslmode=disable"
  ```
- **`CreateEVMAccessorFactory`** reads the secrets file at construction, but does no I/O against the database. It fails if any chain enables the LogPoller and `[db]` is missing: `log_poller_source_reader_enabled on chain <sel> in the EVM config <path> requires [db] in the EVM secrets file`.
- **`chainaccess.GenericConfig.VerifierID`** (`toml:"verifier_id"`) carries the committee verifier's ID to the factory, which uses it to scope filter names. A LogPoller chain fails with `... needs the committee verifier's verifier_id` when it is empty (for example, outside the committee verifier).

### Lazy source reader and reader selection

When the chain has `log_poller_source_reader_enabled`, `accessor.SourceReader()` (`integration/pkg/accessors/evm/logpoller.go`) does the following:

1. Connects and migrates the EVM database on first use (`lazy.Lazy`, 2-minute bound, retried on the next call if it fails).
2. Builds this chain's LogPoller with `standaloneChain.LogPoller(ctx, db)`. It is built once per runtime and not started. Its options match `legacyevm.NewChain`, and it emits Beholder metrics (`logpoller.NewPromBeholderMetrics`), because the standalone process serves no Prometheus endpoint.
3. Returns `NewLogPollerSourceReader(params, cfg)`, where `cfg.Start` takes the EVM database lease and then calls `StartLogPoller`.

Every other chain gets the RPC reader, as before. The verifier logs `Source reader selected` with `reportsFinality` and `reportsHealth` for each chain. `standaloneChain.Close` stops the LogPoller before the head tracker. `ErrAlreadyStopped` and `ErrCannotStopUnstarted` are not errors there.

### EVM database and lease

- **Schema:** `integration/pkg/accessors/evm/migrations/postgres/00001_evm_logpoller_schema.sql` creates the `evm` schema with `log_poller_filters`, `log_poller_blocks`, `logs`, the filter-hash function, and the node's indexes. `00002_evm_lease_lock.sql` adds `evm.lease_lock`. `evmdb.RunPostgresMigrationsContext` records versions in `evm_goose_db_version`, kept apart from the verifier's `goose_db_version`. It is serialized and ctx-aware, and the `noeagerio` analyzer denies it outside startup paths.
- **`evmdb.NewLogPollerDB(*sql.DB) *sqlx.DB`** wraps the shared pool with snake_case mapping for the chainlink-evm ORM. Never close what it returns.
- **`common/dblease`** is a port of the node's `pg` lease lock (chainlink `6fff28e0`, `core/services/pg/lease_lock.go`) to `database/sql`, over a table the caller names. `New(db, lggr, table, cfg)`, `TakeAndHold(ctx, onHeld)`, `Release()`. `DefaultConfig()` uses a 10s query timeout, a 10s lease, and a 1s refresh. If the lease is lost while held, the process exits (`Fatal`), as the node does.
- **Factory lease (`evmLease`):** each factory holds one lease, shared by every accessor it hands out. `Acquire` is serialized and passes the waiting reason to `Loaded()` through `onHeld`. The last `accessor.Close` releases the lease *and then* closes the database, so no write can land after the release.

### Startup load changes

`LogPollerSourceReader.loadLogPoller` now runs these steps, retrying with backoff from 1s up to 1m:

1. **Lease and start:** if `LogPollerConfig.Start` is set (standalone), it takes the lease and starts the LogPoller. In CL mode it is nil, because the node already holds its own lease and runs the LogPoller. While it waits, `Loaded()` reports the reason.
2. Register the filter (unchanged).
3. **Checkpoint must be finalized:** if `fromBlock-1` is above the head tracker's finalized block (as after a testnet reset), the load fails with `CheckpointAboveFinalizedError{Checkpoint, Finalized}` and retries.
4. Anchor an empty LogPoller, then replay. After `Replay`, a finality violation that only shows in `lp.Healthy()` fails the load too.

Other changes:

- **A finality violation during load is final:** the reader sets `finalityBlocked`, counts as loaded, and stops retrying. `FetchMessageSentEvents`, `LatestAndFinalizedBlock`, and `LatestSafeBlock` then return `chain <sel>: finality violated`. Nothing clears this state at runtime, so it lasts until the process or job restarts. Follow the runbook to resolve it.
- **`Loaded()`** returns the last failed attempt, wrapped in `ErrLogPollerNotReady`, so `/health` shows the cause. An attempt cut short by `Close` is not recorded.
- **Block reads before `LoadFrom`:** `LatestAndFinalizedBlock` and `LatestSafeBlock` read the head tracker. That way, a verifier with no checkpoint takes its start block from the chain, not from whatever the LogPoller has stored. Once `LoadFrom` is called, even on a closed reader, they never fall back again.

### Finality and health from the reader

- `LogPollerSourceReader.FinalityViolated()` is true when the reader is `finalityBlocked`, or when `lp.Healthy()` wraps `ErrFinalityViolated`.
- `LogPollerSourceReader.Healthy()` is `lp.Healthy()` with `ErrFinalityViolated` filtered out, so a violation is reported only once.
- `chainaccess.SourceHealthReporter { Healthy() error }` is a new optional `SourceReader` capability. It is wired through `verifier.WithSourceHealthReporters` and then `sourcereader.WithHealthReporter`. A nil reporter adds nothing.
- `sourcereader.Service.Ready()` now fails with `source unhealthy: <err>` when the reporter returns an error. A disabled chain without a finality violation still counts as ready.
- **Chain health gauge (`RecordChainHealthy`):** one function, `chainHealth()` (readiness, then not disabled), now drives it. It is written when the start block initializes, on every load-wait tick, after each successful poll, and when the chain is disabled. The standalone factory now writes `false` when it registers a reader, so a chain is unhealthy until its service reports otherwise. Staleness now starts counting once the source has loaded.
- **CL mode:** `NewVerificationCoordinator` uses `evm.NewLogPollerConfig` and takes the finality reporter from the reader. It does not wire a health reporter.

### Verifier service factory

`cmd/verifier/servicefactory.go`: the verifier database is now opened *after* the source readers are created, and the factory keeps it. `Stop` closes it last, after the coordinator and the admin console. A handle left over from a previous `Start` is closed before reconnecting. `createChainStatusManager` no longer connects to the database. `ConnectToPostgresDB` still returns a true-nil `DataSource` when no URL is configured.

### ccv blocks CLI

`verifier ccv blocks find-lca` and `verifier ccv blocks remove-blocks` (package `integration/pkg/accessors/evm/cli/blocks`) mirror the node's `chainlink blocks find-lca` and `chainlink node remove-blocks`.

| Command | Flags | Behavior |
|---|---|---|
| `find-lca` | `--evm-chain-id` | Read-only, so it is safe with the verifier running. Prints `Last Common Ancestor` with ChainID, Block Hash, and Block Number. Uses `evm.FindLCA`, which runs the LogPoller's `FindLCA` on a LogPoller that is never started, with a client built from the mounted EVM config. |
| `remove-blocks` | `--evm-chain-id`, `--start` (inclusive, > 0) | Waits for the EVM database lease, which a running verifier holds, and logs while it waits. Ctrl-C cancels. Then it deletes `evm.logs` and `evm.log_poller_blocks` rows with block `>= start` (`evm.RemoveBlocksFrom` → `ORM.DeleteLogsAndBlocksAfter`). There is no confirmation and no retention check. |

These checks run before the database is opened:

- The chain ID must map to a known EVM selector (`evm.SelectorFromChainID`).
- The chain must have `log_poller_source_reader_enabled` in the EVM config at `EVM_CONFIG_PATH`.
- For `find-lca` only, the chain's RPC info must be in that config.

The database comes from `[db].url` in the EVM secrets file. It is opened **without migrations**, and `evm.CheckLogPollerSchema` must find `evm.log_poller_blocks`, `evm.logs`, *and* `evm.lease_lock`. If the lease table is missing, the commands refuse to run, because an older verifier that takes no lease could still be writing. `--help` needs none of these.

Runbooks:

- `docs/runbooks/resolving-finality-violation.md` now covers the node and the standalone verifier side by side. Run `set-finalized-height` and `enable` while the service is stopped, then start it.
- `cli/recovery/README.md`, `cli/chainstatuses/README.md`, and `remediating-stuck-or-dropped-messages.md` now say that `reset-reader` and `replay` do not recover a LogPoller chain with a finality violation.

### Test helpers

`testutil.NewTestDB` now also applies the EVM migrations. `testutil.NewTestDBWithURL` returns the connection URL as well, for code that opens its own connection.

### Devenv and CI

- `env-logpoller.toml` overlay with `[verifier.opaque_configs.evm] log_poller_source_reader_chains = ["*"]` (selected by chain ID, or `"*"` for all chains), plus the profiles `standard.logpoller.profile` and `standard.logpoller.src-auto-mine.profile`.
- The EVM devenv registration creates `evm_db` on the verifier's DB server (`chainreg.Registration.VerifierDatabases`, `Registry.ResolveVerifierDatabases`, `committeeverifier.Input.ExtraDatabases`). It also sets `log_poller_source_reader_enabled` on the selected chains and mounts the EVM secrets file.
- `services.CreateBootstrapDBInitScript` (var) is replaced by `services.CreateDBInitScriptFile(dbName)`. DB URLs are now built with `services.PostgresURL`.
- New e2e tests: `logpoller_recovery_test.go` (the finality-violation runbook against the standalone CLI) and updates to `logpoller_in_use_test.go` and `finality_reorg_curse_test.go`. CI adds `TestE2ESmoke_Basic_LogPoller` and `TestE2EReorg_LogPoller` to `test-smoke.yaml`.

## Compatibility & Requirements

- **Feature flag:** `log_poller_source_reader_enabled`, per chain, default false. Chains without it keep the RPC reader, with no change in behavior.
- **Database:** A LogPoller chain needs `[db]` in the EVM secrets file, or `CreateEVMAccessorFactory` fails at boot. The EVM database can be the verifier's own database or a separate one. The `evm` schema and its version table do not collide with the verifier's.
- **One writer per EVM database:** The LogPoller tables are scoped by `evm_chain_id`, not by verifier. A second verifier process on the same EVM database waits on the lease, and its LogPoller chains stay not-ready (`Loaded()` reports the wait) until the first one releases it.
- **Rollback:** Older binaries reject the unknown `log_poller_source_reader_enabled` key in the EVM config, and they do not read the EVM secrets file. Remove the key before rolling back.
- **Dependency bumps:** `github.com/scylladb/go-reflectx v1.0.1` moves from indirect to direct in `go.mod`, for `evmdb.NewLogPollerDB`. The version is unchanged.
- **Monitoring:** Standalone LogPoller metrics go out through Beholder. The chain health gauge now starts unhealthy and follows `chainHealth()`.

## References

- Branch: `feat/CCIP13600-standalone-sr-log-poller`.
- Key commits: `3b7b8c82` per-chain `log_poller_source_reader_enabled`, `f23d5b15` EVM `Secrets`, `7015a153` lazy EVM DB connect and migrate, `023a310b` EVM database lease, `03dd0ab0` `common/dblease`, `0d9dce4a` the EVM accessor owns the LogPoller switch, `f096e1ac` `[Feature]` section removed, `39eb0e0f` / `17f74624` `ccv blocks` moved into the EVM adapter, `406d6899` start from the checkpoint without skipping events, `049035b0` `find-lca` / `remove-blocks`, `f8975d61` combined health on a successful query, `93580d3c` / `5b0af0d3` verifier DB open order and close in `Stop`, `2b28d941` LogPoller smoke and reorg tests in CI.
- Prior changelog entries this builds on: `2026-10-07_source_reader_log_poller.md`, `2026-10-15_reader_runtime_health_probes.md`, `2026-09-11_source_recovery.md`, `2026-10-06_no_eager_io_startup.md`.
