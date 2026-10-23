# Standalone verifier reads EVM source chains through its own LogPoller

## Executive Summary

- The standalone committee verifier can now read `CCIPMessageSent` logs through a LogPoller it runs itself, on its own database. Before this, only the CL-mode verifier did (`2026-10-07_source_reader_log_poller.md`). It is off by default and turned on with `[Feature] LogPoller = true` in the bootstrap config.
- Each chain's LogPoller runs in the verifier process and stores its data in the verifier database, in a new `evm` schema (migration `00001_evm_logpoller_schema.sql`, owned by the EVM accessor). Only one LogPoller per `evm_chain_id` can run in a process.
- The LogPoller reader now reports its own finality violations (`chainaccess.FinalityViolationReporter`) and its own health (new `chainaccess.SourceHealthReporter`). `evm.NewLogPollerFinality` is removed. The chain health gauge now has one source, `sourcereader.Service.chainHealth`.
- The startup load gets two new steps. It waits until the checkpoint is finalized. If the replay hits a finality violation, it stops retrying and blocks the reader.
- New `verifier ccv blocks find-lca` and `remove-blocks` commands mirror the node's commands. The finality-violation runbook now covers both the node and the standalone verifier.
- `bootstrap` gains a `[Feature]` section, plus two optional factory hooks: `FeatureValidator` and `AccessorsClosedHook`. `chainaccess` gains three optional accessor capabilities. Only one public symbol is removed (`evm.NewLogPollerFinality`), and `RunCCVCLI` gets a trailing variadic.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewLogPollerFinality` | removed | `\bNewLogPollerFinality\(` | — | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `constructors.newLogPollerConfig` (unexported) | removed | `\bnewLogPollerConfig\(` | — | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `verifier.RunCCVCLI` (`cmd/verifier`) | signature-changed | `\bRunCCVCLI\(` | `cmd/verifier/run_ccv_cli.go:51` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| EVM `accessor.SourceReader` | behavior-changed | `\.SourceReader\(\)` | `integration/pkg/accessors/evm/factory.go:363` | [#accessor-reader-selection](#accessor-reader-selection) |
| `evm.LogPollerSourceReader.LoadFrom` startup load | behavior-changed | `\.LoadFrom\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:251` | [#startup-load-changes](#startup-load-changes) |
| `evm.LogPollerSourceReader.Loaded` | behavior-changed | `\.Loaded\(\)` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:176` | [#startup-load-changes](#startup-load-changes) |
| `evm.LogPollerSourceReader.LatestAndFinalizedBlock` / `LatestSafeBlock` | behavior-changed | `\.(LatestAndFinalizedBlock\|LatestSafeBlock)\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:468` | [#startup-load-changes](#startup-load-changes) |
| `evm.LogPollerSourceReader.FetchMessageSentEvents` | behavior-changed | `\.FetchMessageSentEvents\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:397` | [#startup-load-changes](#startup-load-changes) |
| `sourcereader.Service.Ready` and chain health gauge | behavior-changed | `RecordChainHealthy\(` | `verifier/pkg/sourcereader/service.go:326` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `constructors.NewVerificationCoordinator` | behavior-changed | `constructors\.NewVerificationCoordinator\(` | `integration/pkg/constructors/committee_verifier.go:345` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `bootstrap.Bootstrapper.Start` and job stop/start | behavior-changed | `bootstrap\.(Run\|NewBootstrapper)\(` | `bootstrap/bootstrap.go:763` | [#bootstrap-hooks](#bootstrap-hooks) |
| Committee verifier factory `Start` / `Stop` | behavior-changed | `NewCommitteeVerifierServiceFactory\(` | `cmd/verifier/servicefactory.go:146` | [#database-and-schema](#database-and-schema) |
| `bootstrap.Features` | added | `\bbootstrap\.Features\b` | `bootstrap/bootstrap.go:73` | [#feature-switch](#feature-switch) |
| `bootstrap.NonSecretConfig.Feature` (`[Feature]`) | added | `^\[Feature\]` | `bootstrap/config.go:348` | [#feature-switch](#feature-switch) |
| `bootstrap.ServiceDeps.Features` | added | `deps\.Features\b` | `bootstrap/bootstrap.go:91` | [#feature-switch](#feature-switch) |
| `bootstrap.LoadFeatures` | added | `\bLoadFeatures\(` | `bootstrap/config.go:528` | [#feature-switch](#feature-switch) |
| `bootstrap.FeatureValidator` | added | `\bFeatureValidator\b` | `bootstrap/bootstrap.go:113` | [#bootstrap-hooks](#bootstrap-hooks) |
| `bootstrap.AccessorsClosedHook` | added | `\bAccessorsClosedHook\b` | `bootstrap/bootstrap.go:121` | [#bootstrap-hooks](#bootstrap-hooks) |
| `chainaccess.SourceReaderDeps` | added | `\bSourceReaderDeps\b` | `pkg/chainaccess/interfaces.go:84` | [#accessor-reader-selection](#accessor-reader-selection) |
| `chainaccess.SourceReaderDepsSetter` | added | `\bSourceReaderDepsSetter\b` | `pkg/chainaccess/interfaces.go:92` | [#accessor-reader-selection](#accessor-reader-selection) |
| `chainaccess.SourceHealthReporter` | added | `\bSourceHealthReporter\b` | `pkg/chainaccess/interfaces.go:77` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `verifier.WithSourceHealthReporters` | added | `\bWithSourceHealthReporters\(` | `verifier/pkg/coordinator.go:87` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `sourcereader.WithHealthReporter` | added | `\bWithHealthReporter\(` | `verifier/pkg/sourcereader/service.go:114` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `evm.LogPollerSourceReader.FinalityViolated` / `Healthy` | added | `\.(FinalityViolated\|Healthy)\(\)` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:146` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `evm.NewLogPollerConfig` | added | `\bNewLogPollerConfig\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:71` | [#finality-and-health-from-the-reader](#finality-and-health-from-the-reader) |
| `evm.CheckpointAboveFinalizedError` | added | `\bCheckpointAboveFinalizedError\b` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:45` | [#startup-load-changes](#startup-load-changes) |
| `evm.LCA`, `evm.FindLCA`, `evm.RemoveBlocksFrom` | added | `\bevm\.(LCA\|FindLCA\|RemoveBlocksFrom)\b` | `integration/pkg/accessors/evm/evm_logpoller_operator.go:29` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| `evm.SelectorFromChainID`, `evm.CheckLogPollerSchema` | added | `\bevm\.(SelectorFromChainID\|CheckLogPollerSchema)\(` | `integration/pkg/accessors/evm/evm_logpoller_operator.go:37` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| `logpollerdb.NewDB` | added | `\blogpollerdb\.NewDB\(` | `integration/pkg/accessors/evm/logpollerdb/postgres.go:12` | [#database-and-schema](#database-and-schema) |
| `blocks` CLI package (`LCA`, `Operator`, `Deps`, `InitBlocksCommandsWithFactory`) | added | `cli/blocks"` | `cli/blocks/commands.go:44` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| `verifier.CLIOption`, `verifier.WithoutBlocks` (`cmd/verifier`) | added | `\bWithoutBlocks\(` | `cmd/verifier/run_ccv_cli.go:37` | [#ccv-blocks-cli](#ccv-blocks-cli) |
| Migration `00001_evm_logpoller_schema.sql` | added | `00001_` | `integration/pkg/accessors/evm/migrations/postgres/00001_evm_logpoller_schema.sql:1` | [#database-and-schema](#database-and-schema) |
| `testutil.NewTestDBWithURL` | added | `\bNewTestDBWithURL\(` | `verifier/testutil/test_db.go:31` | [#database-and-schema](#database-and-schema) |

## Breaking Changes

### evm.NewLogPollerFinality removed

- **What changed:** `evm.NewLogPollerFinality(lp)` and its unexported `logPollerFinality` type are deleted.
- **Before:** A caller built a `chainaccess.FinalityViolationReporter` from the node's LogPoller and passed it in a map to `verifier.WithFinalityReporters`.
- **After:** `*evm.LogPollerSourceReader` implements `chainaccess.FinalityViolationReporter`. Type-assert the reader returned by `evm.NewLogPollerSourceReader` and use that as the reporter.
- **Why:** The reader latches a violation found by its startup replay (`finalityBlocked`). The LogPoller's own flag can be cleared before a poll samples it, so a reporter built only from the LogPoller would miss that violation.
- **Who is affected:** Callers outside `integration/pkg/constructors`. The only in-repo caller is updated, and the Chainlink node calls `constructors.NewVerificationCoordinator`, whose signature does not change.

### RunCCVCLI takes options

- **What changed:** `cmd/verifier.RunCCVCLI(args, secretsEnvVar, defaultSecretsPath string)` becomes `RunCCVCLI(args, secretsEnvVar, defaultSecretsPath string, opts ...CLIOption)`.
- **Who is affected:** Nobody at the source level, because existing calls still compile. A function value typed with the old signature does not compile.

No other public signature changes.

## Migration Guide

1. Replace `evm.NewLogPollerFinality(lp)` with the reader itself:

   ```go
   // Before
   reader, err := evm.NewLogPollerSourceReader(ctx, params, &evm.LogPollerConfig{LogPoller: lp, VerifierID: id, Retention: evm.DefaultMessageSentLogRetention})
   reporter := evm.NewLogPollerFinality(lp)
   ```

   ```go
   // After
   reader, err := evm.NewLogPollerSourceReader(ctx, params, evm.NewLogPollerConfig(lp, id))
   if err != nil { return err }
   reporter, ok := reader.(chainaccess.FinalityViolationReporter)
   if !ok { return errors.New("log poller source reader does not report finality violations") }
   ```

   Do the type assertion on the raw reader, before any instrumentation wrapper. `observedSourceReader` hides these capabilities.
2. Build `evm.LogPollerConfig` with `evm.NewLogPollerConfig`.
3. A `SourceReader` wrapper that must keep the new signals has to forward `FinalityViolated()` and `Healthy()`, or the caller has to resolve them from the raw reader as `selectChainReader` does.
4. Any `bootstrap.ServiceFactory` started in local mode must tolerate `Stop` after a failed `Start` (see [#bootstrap-hooks](#bootstrap-hooks)).
5. To turn on the LogPoller reader for a standalone committee verifier, add the section below to the bootstrap config. Also make sure the verifier secrets file has `[db].url` (or `CL_DATABASE_URL` is set):

   ```toml
   [Feature]
   LogPoller = true
   ```

## Feature switch

`bootstrap.Features` is the new `[Feature]` section of the non-secret bootstrap config (`NonSecretConfig.Feature`, TOML key `Feature`).

| Field | TOML key | Default | Read by |
|---|---|---|---|
| `LogPoller` | `LogPoller` | `false` | Committee verifier: selects the LogPoller reader for EVM source chains. Token verifier: rejects `true` at boot. |

- Bootstrap copies it into `ServiceDeps.Features` on every start, in both JD and local mode.
- `bootstrap.LoadFeatures()` reads only `[Feature]` from `BOOTSTRAPPER_CONFIG_PATH` (default `/etc/config.toml`). It is for tooling that runs outside the service, such as `ccv blocks`. An unknown key under `[Feature]` is an error.
- The devenv `BootstrapInput.Features` (`toml:"features"`) writes the section. `build/devenv/standard.logpoller.profile` (env.toml + env-src-auto-mine.toml + env-logpoller.toml) turns it on for every committee verifier.

## Bootstrap hooks

Both hooks are optional interfaces a `ServiceFactory` may implement.

| Interface | When bootstrap calls it | Committee verifier | Token verifier |
|---|---|---|---|
| `FeatureValidator.ValidateFeatures(Features) error` | Once in `Bootstrapper.Start`, before either mode starts. An error stops the process with `invalid [Feature] configuration: ...`. | With `LogPoller = true`, it loads the secrets file and fails if no database URL is set. | Fails if `LogPoller = true`. |
| `AccessorsClosedHook.AfterAccessorsClosed(ctx) error` | After every `AccessorCloserRegistry.CloseAll`: on a failed `StartJob`, in `StopJob`, on a failed local start, and in `stopLocal`. Called with `context.WithoutCancel`. | Closes the shared verifier DB, once. | — |

Other bootstrap behavior changes:

- `startLocalService` now calls `fac.Stop(ctx)` when `fac.Start` fails, and logs a failed `Stop` as a warning.

## Database and schema

- **Migration `00001_evm_logpoller_schema.sql`** (tracked in its own `evm_goose_db_version` table) creates schema `evm` with `log_poller_filters`, `log_poller_blocks`, `logs`, the `f_log_poller_filter_hash` function, and the node's indexes, including the CCIP `MessageSent`/`ExecutionStateChanged` partial indexes. It no longer runs on every verifier database: only the EVM accessor applies it. `Down` drops all of it.
- **Connection order.** The committee verifier factory now connects to and migrates the database in `Start` before it builds any accessor (`factory.connectDB`, `cmd/verifier/servicefactory.go:639`), because source readers use it. Before, the database was connected later, in `createChainStatusManager`.
- **Ownership.** The factory keeps the `*sqlx.DB` and closes it only in `AfterAccessorsClosed`, never in `Stop`, so accessors and LogPollers can still use it while bootstrap closes them. A handle left over from a previous `Start` is closed with a warning. `createChainStatusManager` now takes the `sqlutil.DataSource` and does no I/O.
- **`logpollerdb.NewDB(*sql.DB) *sqlx.DB`** wraps the shared pool for the chainlink-evm ORM with the snake_case mapper. It reuses the pool, so never `Close` the result.
- `ConnectToPostgresDB` keeps its behavior and still returns a true nil when no URL is set. The new unexported `connectVerifierDB` returns the concrete `*sqlx.DB`.
- `testutil.NewTestDBWithURL(tb)` also returns the connection string, for tests of code that opens its own connection.

## Accessor reader selection

`chainaccess` adds optional `Accessor` capabilities. The verifier type-asserts them after `GetAccessor`.

```go
type SourceReaderDeps struct {
	DB         *sql.DB // borrowed: the accessor never closes it
	VerifierID string
}

type SourceReaderDepsSetter interface {
	SetSourceReaderDeps(deps SourceReaderDeps) error
}
```

Rules for `SetSourceReaderDeps`: call it before the first `SourceReader()` call. Repeating it with the same values does nothing; different values fail. It fails once the reader is built. Anything it starts belongs to the accessor and is released by `Close`. It must not block on network I/O.

**EVM accessor** (`integration/pkg/accessors/evm/logpoller.go:25`, `factory.go:363`):

- `GetAccessor` no longer builds the source reader. It saves `SourceReaderParams`, and the first `SourceReader()` call builds the reader and caches it, or caches the error. An error that `GetAccessor` used to return (`failed to create EVM source reader`) now comes from `SourceReader()`.
- After a successful `SetSourceReaderDeps`, `SourceReader()` returns `NewLogPollerSourceReader`. Otherwise it returns the RPC reader, as before.
- `SetSourceReaderDeps` calls the runtime's `LogPoller(ctx, db)`. On `standaloneChain` (`standalone_chain.go:417`), that call builds and starts the chain's LogPoller once. The LogPoller copies the node's `legacyevm` options and uses an observed ORM and Beholder metrics, because the standalone process has no Prometheus endpoint. Its start context is cancelled in `accessor.Close`.
- **One LogPoller per `evm_chain_id` per process.** A process-wide `logPollerGuard` refuses a second holder with `log poller for evm_chain_id X is already held by chain selector A, refusing chain selector B`. The guard is released when the LogPoller fails to build or start, or when it closes (`ErrAlreadyStopped` counts as closed). Any other close error keeps the chain held. `standaloneChain.Close` stops the LogPoller before the head tracker.

**Committee verifier** (`cmd/verifier/source_reader_selection.go:33`, `selectChainReader`), per chain:

| `Features.LogPoller` | Accessor implements setter | Result |
|---|---|---|
| false | — | RPC reader. Logs `Source reader selected reader=rpc`. |
| true | no | Warns `Accessor cannot read through a LogPoller, using the RPC source reader`; RPC reader. |
| true | yes, setter fails | Chain skipped (no RPC fallback). |
| true | yes | LogPoller reader. The finality reporter (unless the chain is in `DisableFinalityCheckers`) and the health reporter are resolved from the raw reader; if either is missing the chain is skipped. Logs `reader=logpoller`. |

## Finality and health from the reader

- `LogPollerSourceReader.FinalityViolated()` returns true when the startup replay latched a violation or the LogPoller's `Healthy()` is `ErrFinalityViolated`.
- `LogPollerSourceReader.Healthy()` returns the LogPoller's `Healthy()`, except that `ErrFinalityViolated` becomes `nil`, so a violation is counted only once.
- `chainaccess.SourceHealthReporter { Healthy() error }` reaches each chain's service through `verifier.WithSourceHealthReporters(map)` and then `sourcereader.WithHealthReporter`. A nil entry adds no health input.
- CL mode: `constructors.newChainSourceReader` (`committee_verifier.go:345`) now builds the config with `evm.NewLogPollerConfig(lp, verifierID)`, and uses the reader itself as the finality reporter. CL mode does not pass a health reporter.

**`sourcereader.Service` health** (`verifier/pkg/sourcereader/service.go:326`):

- `Ready()` now runs `readiness()`. The checks, in order: start block initialized, source loaded, **health reporter healthy** (new; error `source unhealthy: ...`), not finality-blocked, not stale.
- `chainHealth()` is `readiness()` plus "not disabled". `recordChainHealth` is now the only writer of the `RecordChainHealthy` gauge. It runs on a failed start-block init, on every loop while waiting for the load, after each successful poll, on a disabled state, and after `handleFinalityViolation`.
- Before, a successful poll always recorded the chain healthy, and a source that finished loading after start was recorded healthy only once (`awaitingLoad` / `recordLoadedHealth`, both removed). Now a successful poll records healthy only if the source's health and the chain's other inputs are healthy.
- The staleness clock (`lastSuccessfulQuery`) now starts when the source finishes loading, not when the start block is set, so a long load does not count as staleness.
- The standalone factory now records each chain **unhealthy** once its reader is instrumented (it used to record healthy). After that, the service is the only writer. Dashboards will show a chain unhealthy until its service's first health check passes.

## Startup load changes

These build on the load described in `2026-10-07_source_reader_log_poller.md`. `loadLogPoller` (`evm_logpoller_source_reader.go:251`) now runs:

1. Register the filter.
2. **Check the start block is finalized** (new). If the checkpoint (`fromBlock - 1`) is above the head tracker's finalized block, as after a testnet reset, the attempt fails with `evm.CheckpointAboveFinalizedError{Checkpoint, Finalized}` and is retried until finality catches up.
3. Anchor an empty LogPoller.
4. Replay. After `Replay`, the LogPoller's `Healthy()` is checked again, because `Replay` hands blocks past its stored finalized block to the poll loop and drops their errors.

Other changes:

- **Finality violation during the load:** the reader does not retry. It sets `finalityBlocked` and `ready`, so the service sees a loaded reader and its finality check disables the chain. It logs `Log poller startup hit a finality violation, not retrying`. While blocked, `FetchMessageSentEvents`, `LatestAndFinalizedBlock`, and `LatestSafeBlock` return `chain <sel>: finality violated`. Only the unexported `clearFinalityBlock` clears the block, and only tests call it, so in practice it lasts until the process or job restarts. Clear it with the runbook, which restarts the verifier.
- **`Loaded()`** now returns the last failed attempt wrapped in `ErrLogPollerNotReady`, so `/health` shows the cause. An attempt cut short by `Close` is not recorded.
- **Block reads before `LoadFrom`:** `LatestAndFinalizedBlock` and `LatestSafeBlock` read the head tracker until `LoadFrom` is called. A verifier with no checkpoint gets its start block from the chain, not from whatever the LogPoller has stored. Once `LoadFrom` is called, even on a closed reader, they never fall back again.
- Retry backoff is still 1s to 1m. Unexported per-reader overrides exist for tests.

## Filter lifecycle

Unchanged from `2026-10-07_source_reader_log_poller.md`: the reader registers `ccv-verifier - <verifierID>:<onramp>` on load and unregisters only that filter on `Close`. Nothing deletes other stored filters.

## ccv blocks CLI

New `cli/blocks` package. The verifier binary adds `verifier ccv blocks find-lca` and `verifier ccv blocks remove-blocks`, which mirror the node's `chainlink blocks find-lca` and `chainlink node remove-blocks`.

| Command | Flags | Behavior |
|---|---|---|
| `find-lca` | `--evm-chain-id` | Read-only. Prints `Last Common Ancestor` with ChainID / Block Hash / Block Number, in the node's format. Uses `evm.FindLCA`, which runs the LogPoller's `FindLCA` on a LogPoller that is never started. |
| `remove-blocks` | `--evm-chain-id`, `--start` (> 0, inclusive) | Deletes `evm.logs` and `evm.log_poller_blocks` rows with block `>= start` (`evm.RemoveBlocksFrom` → `ORM.DeleteLogsAndBlocksAfter`). The verifier must be stopped. There is no lock, no confirmation, and no retention check. |

Checks run before the database is opened: `[Feature] LogPoller` must be true (read with `bootstrap.LoadFeatures`), the chain ID must be a known EVM chain (`evm.SelectorFromChainID`), and, for `find-lca` only, the chain must be in the EVM config at `EVM_CONFIG_PATH`. The database comes from the secrets file `[db].url` or `CL_DATABASE_URL`. It is opened **without migrations**, and `evm.CheckLogPollerSchema` must find the `evm` tables. `--help` needs none of these.

The token verifier passes `cmd.WithoutBlocks("the token verifier has no LogPoller")`. Its commands stay registered and fail with `ccv blocks is not available: ...`.

The runbooks changed to match:

- `docs/runbooks/resolving-finality-violation.md` now covers node and standalone side by side. `enable` and `set-finalized-height` run while the service is stopped.
- `cli/recovery/README.md`, `cli/chainstatuses/README.md`, and `remediating-stuck-or-dropped-messages.md` now say that `reset-reader` and `replay` do not recover a LogPoller chain with a finality violation.

## Compatibility & Requirements

- **Database:** With `LogPoller = true`, the committee verifier needs a database, or it exits at boot. The EVM accessor's migration adds the `evm` schema, and only when a LogPoller is first built.
- **Config rollback:** The bootstrap config is decoded strictly. A config that contains `[Feature]` fails to load on binaries older than this change, so remove the section before rolling back.
- **Token verifier:** It exits at boot if `[Feature] LogPoller = true`. Leave the switch out of the token verifier's bootstrap config.
- **One verifier per database per chain:** The LogPoller tables are scoped by `evm_chain_id`, not by verifier. Two processes that share a database and a chain would both write the same rows. The in-process guard does not stop this across processes.
- **Dependency bumps:** `github.com/scylladb/go-reflectx v1.0.1` moves from indirect to a direct requirement in `go.mod`, for `logpollerdb.NewDB`. The version is unchanged.
- **Monitoring:** Standalone LogPoller metrics go out through Beholder (`logpoller.NewPromBeholderMetrics`). The chain health gauge now starts unhealthy and follows `chainHealth()`.

## References

- Branch: `feat/CCIP13600-standalone-sr-log-poller`.
- Commits: `0cb582d0` feature flag config, `e33dd569` LogPoller DB setup, `a2566b4d` DB-first startup and closing order, `7f53bbe7` single LogPoller per chain, `dd6e8c4c` use the LogPoller behind the flag, `fb64aa5b` stale and orphaned filter cleanup, `a44e12eb` finality violation disables the chain, `5263bd58` LogPoller health metrics, `f64db4c5` no startup delete, `406d6899` start from the checkpoint without skipping events, `049035b0` `find-lca` / `remove-blocks`, `f8975d61` combined health on a successful query, `fcb6968a` source state cleaner naming, `68554e45` DB close alignment.
- Prior changelog entries this builds on: `2026-10-07_source_reader_log_poller.md`, `2026-10-15_reader_runtime_health_probes.md`, `2026-09-11_source_recovery.md`.
