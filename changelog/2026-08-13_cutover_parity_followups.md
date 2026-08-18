# Cutover parity follow-ups: verifier polling, conversion warnings, monitoring cleanup

## Executive Summary

- The verifier's source-reader head fetch is now bounded by the dedicated poll timeout instead of
  the poll interval, and both constructors (CL and standalone) share one 2s poll interval —
  standalone's 1s polling doubled RPC load and halved the head-fetch budget relative to CL.
- The Chainlink-node config converter now warns on every chain-level setting the operator set that
  standalone drops (gas, node-pool, head-tracker, transaction tuning), so custom tuning surfaces at
  startup instead of silently reverting to chain defaults.
- The deprecated app-config `[Monitoring]` sections are settled as ignored in both apps: the
  documented-but-never-implemented fallback promise is deleted, the dead `SetupMonitoring` helpers
  are gone, and the executor no longer validates the section.
- `SourceConfig.RMNRemoteAddress` is removed (both modes wrote it, nothing read it), and the
  executor now fails startup on a pyroscope error like the verifier, token verifier, and bootstrap
  already did.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `vtypes.SourceConfig.RMNRemoteAddress` | removed | `RMNRemoteAddress\b` | `verifier/pkg/vtypes/types.go` | [Removed dead fields and helpers](#removed-dead-fields-and-helpers) |
| `executor.SetupMonitoring` (cmd/executor) | removed | `SetupMonitoring` | `cmd/executor/common.go` | [Removed dead fields and helpers](#removed-dead-fields-and-helpers) |
| `verifier.SetupMonitoring` (cmd/verifier) | removed | `SetupMonitoring` | `cmd/verifier/common.go` | [Removed dead fields and helpers](#removed-dead-fields-and-helpers) |
| `sourcereader.Service` head fetch | behavior-changed | `readyToQuery` | `verifier/pkg/sourcereader/service.go:270` | [Head-fetch timeout and poll interval](#head-fetch-timeout-and-poll-interval) |
| `evm.Conversion.Warnings` | behavior-changed | `dropped set chain-level settings` | `integration/pkg/accessors/evm/clnode_config.go:78` | [Dropped-setting conversion warnings](#dropped-setting-conversion-warnings) |
| `executor.Configuration.Validate` | behavior-changed | `func \(c \*Configuration\) Validate` | `executor/config.go:98` | [Deprecated monitoring sections](#deprecated-monitoring-sections) |
| `executor.Factory.Start` | behavior-changed | `func \(f \*Factory\) Start` | `cmd/executor/service.go:106` | [Pyroscope failure handling](#pyroscope-failure-handling) |
| `verifier.SourceReaderPollInterval` | added | `SourceReaderPollInterval` | `verifier/pkg/vtypes/types.go:47` | [Head-fetch timeout and poll interval](#head-fetch-timeout-and-poll-interval) |

## Breaking Changes

### `SourceConfig.RMNRemoteAddress` removed

- **What:** the field, its JSON tag, and the three writer sites (CL constructor, standalone service
  factory, token verifier) are gone.
- **Before:** `vtypes.SourceConfig` carried `RMNRemoteAddress protocol.UnknownAddress
  \`json:"rmn_remote_address"\``, populated by both deployment modes.
- **After:** the struct has no RMN field; the address reaches accessors through
  `chainaccess.CommitteeConfig.RMNRemoteAddresses` as before.
- **Why:** nothing ever read the field — curse checking runs through `RMNCurseReader` interfaces,
  not the address — and nothing serializes `SourceConfig`, so the JSON tag was vestigial.
- **Who:** consumer repos constructing `verifier.SourceConfig` with the field must drop the line;
  no runtime or persistence migration is needed.

### `SetupMonitoring` helpers removed

- **What:** `SetupMonitoring` in `cmd/executor` and `cmd/verifier` is deleted.
- **Why:** both built beholder monitoring from the deprecated app-config `[Monitoring]` section and
  had no production callers (the executor's was referenced only by a test). They embodied the
  fallback that was documented but never wired.
- **Who:** these live in `main` packages and are unlikely to be imported; any external caller
  should build monitoring from the bootstrap config path (`bootstrap.Config.Monitoring`) instead.

## Behavior Changes

### Head-fetch timeout and poll interval

`readyToQuery` bounded its latest/finalized/safe head fetches with the source reader's poll
interval, so a faster poll meant a smaller RPC budget: standalone polled at 1s against CL's 2s,
doubling poll load and halving the fetch budget at the same time. The head fetch now uses
`SourceConfig.PollTimeout` (default 10s), the setting that already bounded the event-log fetch, and
its comment reflects both uses.

Both constructors now set `PollInterval` from the shared `verifier.SourceReaderPollInterval`
constant (2s, re-exported from `vtypes`), so the modes cannot drift again. The token verifier's
separate 1s poll in `createSourceConfigs` is unchanged — it is a different process, not part of
the CL/standalone committee parity surface.

### Dropped-setting conversion warnings

The node-config converter carries over nodes, finality, and the TXM v2 block time; everything else
under a chain's `Chain` section reverted to chain defaults without a word, contradicting the
factory's own "nothing goes missing silently" comment. The conversion now walks the merged
operator config before node defaults are applied and emits one warning per chain listing every
set-but-dropped setting by dotted path, e.g.:

```
chain 11155111: dropped set chain-level settings with no standalone equivalent: GasEstimator.Mode, HeadTracker.HistoryDepth
```

Carried-over settings (`FinalityDepth`, `FinalityTagEnabled`,
`Transactions.TransactionManagerV2.BlockTime`) never warn. A chain that sets nothing extra produces
no warning, so clean conversions stay quiet. This is also the cheap half of the pre-cutover
settings diff: the startup log now enumerates what needs review per chain.

### Deprecated monitoring sections

Both apps' app-config `[Monitoring]` sections are deprecated and had no runtime consumer in either
mode, yet their comments promised a fallback to them when bootstrap monitoring was absent — a
fallback `initMonitoring` deliberately never implemented. The comments on
`bootstrap.Config.Monitoring`, `executor.Configuration.Monitoring`, and `commit.Config.Monitoring`
(now in the generated config references) state the actual behavior: the sections are ignored,
retained so older job specs still decode, and intentionally not validated.

Consistent with that, `executor.Configuration.Validate` no longer validates the section (previously
a spec with `Beholder.Enabled = true` and unset beholder intervals failed startup in both modes for
a knob nothing read); the verifier never validated its section, so the components now agree. The
bootstrap config's own `[Monitoring]` section is unaffected and still validated when present.

### Pyroscope failure handling

The executor logged a pyroscope start error and continued, while the committee verifier, token
verifier, and bootstrap all fail startup. The executor now returns `failed to start pyroscope:
%w` from `Factory.Start`, and `Factory.Stop` joins the profiler's stop error into its shutdown
error instead of discarding it.

## Decisions recorded

No code change; the rationale is written down where the next reader will find it.

- **Executor config defaulting parity (B1).** Normalization is the standalone-side answer for
  omitted fields: `GetNormalizedConfig` is documented as standalone-only, CL deliberately validates
  without defaulting, and the changesets marshal one explicit config into both envelopes. A new
  test proves normalization is the identity on a fully explicit production spec and that the two
  zero-fallbacks match CL's in-constructor safety nets (`executor/config_test.go`).
- **`disable_finality_checkers` (B7).** Standalone honors it, CL ignores it; EVM standalone jobs
  must not set it (the node never disabled checking), and the field remains for chain families
  whose standalone deployments predate parity work. Recorded on the field comment
  (`verifier/pkg/commit/config.go:203`) and in the migration procedure's "Finality checking stays
  on" section.
- **Head-tracker persistence (D3).** The standalone EVM head tracker runs in-memory; a restart
  re-syncs from RPC where the node resumed from persisted heads — catch-up time, not correctness.
  Recorded at `integration/pkg/accessors/evm/chainlink_config.go:47` and in the migration
  procedure's "Flagged for update" section.
- **Local-mode reload (D4).** Local app config is read once at start; edits require a restart.
  Documented in `bootstrap/README.md`.
- **Executor identity check (F5).** No post-boot assertion: the executor publishes its own
  transmitter address to JD, so registration plus the operator's funding step is sufficient.
  Recorded in the migration procedure's "Why the executor's transmitter is new".
- **Cutover batching (F7).** Max concurrent cutovers = committee size − threshold (16 − 9 = 7 for
  the default committee), derived not hardcoded; written into the migration procedure.
- **`txm_block_time` fallback (A2).** The 2s TXM v2 block-time fallback and the need to agree
  per-chain values before cutover are now stated in the migration procedure's "Why the node's TOML
  is reused as-is". Per-chain values themselves remain an ops task.

## Compatibility & Requirements

- No dependency changes.
- Strict app-config decoding still accepts specs carrying a deprecated `[Monitoring]` section; the
  sections decode and are ignored.
- Specs with `Beholder.Enabled = true` and invalid beholder intervals in the executor's deprecated
  `[Monitoring]` section no longer fail validation — no production spec sets it.
- The conversion warnings add log lines only; converted configs are unchanged.

## References

- Prior changelog entries: `2026-08-13_standalone_executor_observability.md`,
  `2026-08-11_cutover_parity_cleanup.md`, `2026-08-11_standalone_verifier_observability.md`
- Migration procedure: `docs/migration/evm-cl-to-standalone.md` ("Why the node's TOML is reused
  as-is", "Finality checking stays on", "How many operators can migrate at once")
