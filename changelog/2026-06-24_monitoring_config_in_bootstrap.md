# Monitoring config sourced from the operator bootstrap config

## Executive Summary

- Monitoring config (`pkg/monitoring.Config`) for the commit (committee) verifier
  and the executor now comes from the operator-provided **bootstrap config**, not
  the JD-shipped **app config**.
- It's operator- and environment-specific (OTel exporter endpoints point at a
  collector deployed alongside the app), so it belongs with the other operator-
  owned settings (keystore password, DB URL, JD connection), not in config that
  is common across all operators.
- Affects: `bootstrap`, `cmd/verifier`, `cmd/executor`, the `ApplyVerifierConfig`
  / `ApplyExecutorConfig` changesets, devenv bootstrap generation, and any
  operator-authored bootstrap config TOML.
- Breaking: the `Monitoring` inputs were removed from the verifier/executor
  changesets, and operators must add `[monitoring]` to each app's bootstrap
  config. The app-config `Monitoring` field is kept-but-deprecated as a
  backwards-compatible fallback (decoding is strict, so removing it would crash
  on stale JD job specs).
- The **token verifier is unchanged**: it loads no bootstrap config and keeps
  monitoring in its (already operator-provided) mounted app config.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.ApplyVerifierConfigInput.Monitoring` | removed | `ApplyVerifierConfigInput\{` | — | [#changeset-monitoring-inputs-removed](#changeset-monitoring-inputs-removed) |
| `changesets.ApplyExecutorConfigInput.Monitoring` | removed | `ApplyExecutorConfigInput\{` | — | [#changeset-monitoring-inputs-removed](#changeset-monitoring-inputs-removed) |
| `changesets.AddNOPOffchainInput.Monitoring` | removed | `AddNOPOffchainInput\{` | — | [#changeset-monitoring-inputs-removed](#changeset-monitoring-inputs-removed) |
| `commit.Config.Monitoring` | deprecated | `commit\.Config\b` | `verifier/pkg/commit/config.go:186` | [#app-config-monitoring-deprecated](#app-config-monitoring-deprecated) |
| `executor.Configuration.Monitoring` | deprecated | `executor\.Configuration\b` | `executor/config.go:53` | [#app-config-monitoring-deprecated](#app-config-monitoring-deprecated) |
| `bootstrap.Config.Monitoring` | added | `bootstrap\.Config\b` | `bootstrap/config.go:106` | [#bootstrap-config-monitoring-added](#bootstrap-config-monitoring-added) |
| `bootstrap.ServiceDeps.Monitoring` | added | `ServiceDeps\b` | `bootstrap/bootstrap.go:54` | [#servicedeps-monitoring-added](#servicedeps-monitoring-added) |
| `services.BootstrapInput.Monitoring` (devenv) | added | `BootstrapInput\{` | `build/devenv/services/bootstrap.go:32` | [#devenv-bootstrapinput-monitoring-added](#devenv-bootstrapinput-monitoring-added) |

## Breaking Changes

### Changeset monitoring inputs removed

- **What changed:** the `Monitoring` field was removed from
  `changesets.ApplyVerifierConfigInput`, `changesets.ApplyExecutorConfigInput`,
  and `changesets.AddNOPOffchainInput`. The changesets no longer marshal a
  `[monitoring]` section into the verifier/executor JD job specs.
- **Before:** callers set `Monitoring: <monitoring.Config>` on these inputs, and
  it was emitted into the job spec consumed by `commit.Config.Monitoring` /
  `executor.Configuration.Monitoring`.
- **After:** the field is gone (consumers setting it will not compile). Monitoring
  must be provided through the bootstrap config instead.
- **Why:** monitoring is operator-owned; the JD-shipped app config is meant to be
  common across operators, so it was the wrong delivery channel.
- **Who is affected:** any code (deploy repos, devenv forks) constructing these
  changeset inputs with `Monitoring` set.

### Operator bootstrap config must carry `[monitoring]`

- **What changed:** the deployed commit verifier and executor read monitoring from
  the bootstrap config (`/etc/config.toml`), not the JD job spec.
- **Before:** `[monitoring]` lived in the JD-shipped app config.
- **After:** `[monitoring]` (and `[monitoring.Beholder]`) must be present in the
  bootstrap config file the operator mounts. If absent, the app falls back to the
  deprecated app-config field; once that is removed, absence means monitoring is
  disabled.
- **Why:** see above.
- **Who is affected:** operators of the commit verifier and executor. The token
  verifier is unaffected (it keeps monitoring in its mounted app config).

## Migration Guide

1. Remove `Monitoring:` from any `ApplyVerifierConfigInput` /
   `ApplyExecutorConfigInput` / `AddNOPOffchainInput` literals — they no longer
   compile.

   ```go
   // Before
   changesets.ApplyVerifierConfigInput{
       CommitteeQualifier: q,
       // ...
       Monitoring: myMonitoringConfig,
   }
   ```

   ```go
   // After — Monitoring is dropped; route it into the bootstrap config instead.
   changesets.ApplyVerifierConfigInput{
       CommitteeQualifier: q,
       // ...
   }
   ```

2. Add a `[monitoring]` section to each commit-verifier and executor bootstrap
   config (the file at `BOOTSTRAPPER_CONFIG_PATH`, default `/etc/config.toml`):

   ```toml
   [monitoring]
   Enabled = true
   Type = "beholder"

   [monitoring.Beholder]
   OtelExporterGRPCEndpoint = "localhost:4317"
   MetricReaderInterval = 10
   TraceSampleRatio = 1.0
   TraceBatchTimeout = 5
   ```

3. If you generate bootstrap configs programmatically (devenv-style), populate
   `services.BootstrapInput.Monitoring` (devenv) or `bootstrap.Config.Monitoring`
   directly — `GenerateBootstrapConfig` marshals it through.

4. Do not remove `[monitoring]` from existing JD job specs by hand: the deprecated
   app-config field still decodes them (decoding is strict), and the app uses them
   as a fallback until the bootstrap config provides monitoring. New specs no
   longer emit the section.

## New Features / Additions

### bootstrap.Config.Monitoring added

`bootstrap.Config` gained `Monitoring *monitoring.Config` (`bootstrap/config.go:106`).
It is optional and validated only when non-nil. It is a **pointer** so that
"operator did not configure monitoring here" (`nil`) is distinguishable from
"operator explicitly configured it, possibly with `Enabled=false`" (non-nil).

### ServiceDeps.Monitoring added

`bootstrap.ServiceDeps` gained `Monitoring *monitoring.Config`
(`bootstrap/bootstrap.go:54`), populated from `Config.Monitoring` on the JD startup
path only. Static-TOML mode (the token verifier) leaves it `nil`. Service factories
read it to obtain operator-provided monitoring.

### devenv BootstrapInput.Monitoring added

`services.BootstrapInput` (devenv) gained `Monitoring *monitoring.Config`
(`build/devenv/services/bootstrap.go:32`); `GenerateBootstrapConfig` copies it into
the generated `bootstrap.Config`. devenv routes the central monitoring config
(`obs.Monitoring` / `topology.Monitoring`) into each service's bootstrap input.

## Deprecations

### App-config monitoring deprecated

- **`commit.Config.Monitoring`** (`verifier/pkg/commit/config.go:186`) and
  **`executor.Configuration.Monitoring`** (`executor/config.go:53`) — deprecated in
  favor of `bootstrap.Config.Monitoring`. Retained only so pre-existing JD job
  specs carrying a `[monitoring]` section still decode (decoding is strict), and
  read only as a fallback when the bootstrap config does not configure monitoring.
- **Planned removal:** once all deployments source monitoring from the bootstrap
  config. The cleanup will also delete the `ServiceDeps`-with-fallback read path
  and may demote `bootstrap.Config.Monitoring` / `ServiceDeps.Monitoring` from
  `*monitoring.Config` to a value type.

## Compatibility & Requirements

- **No hard runtime break.** The kept-but-deprecated app-config field means a new
  binary reading a stale JD spec (still carrying `[monitoring]`) decodes *and* uses
  it via fallback, and an old binary reading a regenerated spec (no `[monitoring]`)
  decodes to a zero value. Strict decoding cannot crash either direction.
- **Operator action required:** add `[monitoring]` to each commit-verifier and
  executor bootstrap config. If skipped, monitoring silently falls to noop — never
  a crash, only an observability gap.
- **Rollout ordering (for monitoring continuity):** add `[monitoring]` to the
  bootstrap config and **roll the new binaries first, then regenerate/push the JD
  specs** (dropping `[monitoring]`). Regenerating specs *before* old binaries are
  upgraded blanks those binaries' monitoring until they roll — no crash, just a
  transient gap. Effective monitoring source by binary/spec/bootstrap combination:

  | Binary | Spec `[monitoring]` | Bootstrap `[monitoring]` | Monitoring |
  |---|---|---|---|
  | new | present (stale) | absent | on (app-config fallback) |
  | new | either | present | on (bootstrap wins) |
  | new | absent (regenerated) | absent | off |
  | old | absent (regenerated) | n/a | off |

## References

- Commits: `bootstrap: source monitoring from operator config`;
  `deployment,devenv: drop monitoring from JD config`
- Prior changelog entries this builds on: `2026-04-24_executor_bootstrap.md`,
  `2026-04-29_bootstrap_withkey.md`
