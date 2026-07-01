# Token verifier adopts bootstrap operator config for monitoring

## Summary

The token verifier now sources monitoring config from the bootstrap TOML
(`BOOTSTRAPPER_CONFIG_PATH`) in addition to its existing app config path, resolving the
exception documented in the previous changelog. This is the prerequisite for a
structured OTel log-streaming logger constructed in bootstrap code and delivered via
`ServiceDeps.Logger`. The change is backwards compatible — existing deployments without
a bootstrap config file continue to read monitoring from the app config as before.

- Affects: `bootstrap`, `cmd/verifier/token`, `build/devenv/services`
- Does **not** affect the commit verifier or executor (their paths are unchanged)

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `bootstrap.Config` infra fields | changed | `bootstrap\.Config\b` | `bootstrap/config.go:123` | [#config-validate-mode-aware](#config-validate-mode-aware) |
| `bootstrap.ServiceDeps.Monitoring` | changed | `ServiceDeps\b` | `bootstrap/bootstrap.go:57` | [#servicedeps-now-populated-in-static-toml-mode](#servicedeps-now-populated-in-static-toml-mode) |
| `bootstrap.WithJD` + `bootstrap.WithTOMLAppConfig` | changed | `WithJD\(\)\|WithTOMLAppConfig\(` | `bootstrap/bootstrap.go` | [#withJD-and-withtomLappconfig-are-now-mutually-exclusive](#withJD-and-withtomLappconfig-are-now-mutually-exclusive) |
| `token.Config.Monitoring` | deprecated | `token\.Config\b` | `verifier/pkg/token/config.go` | [#token-verifier-app-config-monitoring-deprecated](#token-verifier-app-config-monitoring-deprecated) |
| `services.NewTokenVerifier` (devenv) | changed | `NewTokenVerifier\(` | `build/devenv/services/tokenVerifier.go:62` | [#devenv-two-config-files](#devenv-two-config-files) |

---

## Breaking change: `WithJD` and `WithTOMLAppConfig` are now mutually exclusive

Previously, calling both options on the same bootstrapper silently picked JD mode and
ignored the app config path. `NewBootstrapper` now returns an error immediately.

```go
// Before — silently started in JD mode, WithTOMLAppConfig was ignored
b, _ := bootstrap.NewBootstrapper("svc", lggr, fac,
    bootstrap.WithJD(),
    bootstrap.WithTOMLAppConfig("/etc/app.toml"),
)

// After — returns: "WithJD and WithTOMLAppConfig are mutually exclusive"
b, err := bootstrap.NewBootstrapper("svc", lggr, fac,
    bootstrap.WithJD(),
    bootstrap.WithTOMLAppConfig("/etc/app.toml"),
)
```

This is unlikely to affect real callers (the combination was always wrong), but worth
checking if any test or integration harness constructed bootstrappers this way.

---

## New: operator config loading in static-TOML mode

`NewBootstrapper` in static-TOML mode (`WithTOMLAppConfig`) now optionally loads a
bootstrap TOML from `BOOTSTRAPPER_CONFIG_PATH` **when that env var is explicitly set**.
If present, `[monitoring]` (and any future operator sections) are decoded and surfaced
via `ServiceDeps.Monitoring`.

The default fallback to `/etc/config.toml` is **intentionally suppressed** in
static-TOML mode: the token verifier's `TOKEN_VERIFIER_CONFIG_PATH` and the bootstrap
`BOOTSTRAPPER_CONFIG_PATH` both default to that path, so applying the default would
silently decode the wrong file. Set the env var explicitly to opt in.

```toml
# /etc/bootstrap-config.toml  (operator mounts this alongside the app config)
[monitoring]
Enabled = true
Type = "beholder"

[monitoring.Beholder]
OtelExporterGRPCEndpoint = "localhost:4317"
MetricReaderInterval = 10
TraceSampleRatio = 1.0
TraceBatchTimeout = 5
```

```sh
BOOTSTRAPPER_CONFIG_PATH=/etc/bootstrap-config.toml
TOKEN_VERIFIER_CONFIG_PATH=/etc/token-verifier-app-config.toml
```

---

## New: `ServiceDeps.Logger` and `ServiceDeps.Monitoring` populated in static-TOML mode

`startWithAppConfig` previously handed service factories an almost-empty `ServiceDeps`
(only `Registry` was set). It now constructs a full `ServiceDeps`:

| Field | Before | After |
|---|---|---|
| `Logger` | `nil` | built from `WithLogLevelFromEnv` / `WithLogLevel` option |
| `Registry` | set | set (unchanged) |
| `Keystore` | `nil` | `nil` (no keystore in static-TOML mode) |
| `Monitoring` | `nil` | set from bootstrap config when loaded; `nil` otherwise |

Service factories in static-TOML mode should use `deps.Logger` directly instead of
constructing their own logger.

---

## New: mode-aware bootstrap config validation {#config-validate-mode-aware}

`bootstrap.Config.validate()` is now **mode-driven**: it validates the infra bundle
(`[jd]`, `[db]`, `[keystore]`, `[server]`) only when the bootstrapper runs in JD mode
(the caller passes `needsInfra=true`, derived from the `jdMode` flag). In static-TOML
mode (`needsInfra=false`) the infra bundle is ignored — any infra section present is
logged as a warning, not an error. Monitoring is always validated independently, in both
modes. This makes a monitoring-only bootstrap TOML valid:

```toml
# Valid for token verifier — no infra sections required
[monitoring]
Enabled = true
Type = "beholder"

[monitoring.Beholder]
OtelExporterHTTPEndpoint = "host.docker.internal:4318"
LogStreamingEnabled = true
MetricReaderInterval = 10
TraceSampleRatio = 1.0
TraceBatchTimeout = 5
```

The infra struct fields (`JD`, `Keystore`, `DB`, `Server`) also carry `omitempty` TOML
marshal tags so that marshaling a monitoring-only `bootstrap.Config` does not emit empty
infra sections — which, on reload in static-TOML mode, would otherwise be logged as
"ignored infra section" warnings.

---

## Deprecation: token verifier app-config monitoring {#token-verifier-app-config-monitoring-deprecated}

`token.Config.Monitoring` is now deprecated. The token verifier reads monitoring via
`bootstrap.ResolveMonitoring(deps.Monitoring, cfg.Monitoring)`, preferring the bootstrap
config and falling back to the app-config field only when `deps.Monitoring` is `nil`
(i.e. no bootstrap config is loaded). This is the same F2 fallback pattern introduced
for the commit verifier and executor in the previous migration.

**Planned removal:** once all token verifier deployments mount a bootstrap config,
remove `token.Config.Monitoring` and the fallback call in the factory.

---

## Devenv: two config files for the token verifier {#devenv-two-config-files}

`services.NewTokenVerifier` now generates and mounts two files:

| File | Container path | Env var |
|---|---|---|
| App config (blockchain infos, verifier config) | `/etc/token-verifier-app-config.toml` | `TOKEN_VERIFIER_CONFIG_PATH` |
| Bootstrap config (monitoring only) | `/etc/config.toml` | `BOOTSTRAPPER_CONFIG_PATH` |

The `[Monitoring]` section has been removed from `tokenVerifier.template.toml`; it is
now carried solely by the bootstrap config. This also fixes a pre-existing bug where the
app config was mounted at `aggregator.DefaultConfigFile` (`/etc/config.toml`) instead
of a token-verifier-specific path.

---

## Migration guide: token verifier in production

The change is **backwards compatible**. No immediate action is required — monitoring
continues to be read from the app config via the F2 fallback until you opt in.

### Step 1 — add a bootstrap config for the token verifier

Create a new TOML file that the token verifier can mount as its operator config. It only
needs the monitoring section — no DB, JD, keystore, or server entries:

```toml
# token-verifier-operator-config.toml
[monitoring]
Enabled = true
Type = "beholder"

[monitoring.Beholder]
OtelExporterGRPCEndpoint = "<your-otel-collector>:4317"  # or HTTP endpoint below
# OtelExporterHTTPEndpoint = "<your-otel-collector>:4318"
InsecureConnection = false
CACertFile = ""
LogStreamingEnabled = true
MetricReaderInterval = 10
TraceSampleRatio = 1.0
TraceBatchTimeout = 5
```

### Step 2 — mount the file and set the env var

In your k8s deployment, mount the new ConfigMap alongside the existing app config and
set `BOOTSTRAPPER_CONFIG_PATH`:

```yaml
env:
  - name: TOKEN_VERIFIER_CONFIG_PATH
    value: /etc/token-verifier/app-config.toml   # wherever your app config is mounted
  - name: BOOTSTRAPPER_CONFIG_PATH
    value: /etc/token-verifier/operator-config.toml
volumeMounts:
  - name: app-config
    mountPath: /etc/token-verifier/app-config.toml
    subPath: config.toml
  - name: operator-config
    mountPath: /etc/token-verifier/operator-config.toml
    subPath: operator-config.toml
```

### Step 3 — roll the binary

Deploy the new binary. On startup it will log:

```
loaded operator config for static-TOML mode
Using monitoring config from bootstrap config
```

Monitoring continues uninterrupted. The app-config `[monitoring]` field is now ignored
(bootstrap wins); you can leave it in place or remove it from the app config at your
convenience — it is no longer read.

### Rollout matrix

| Binary | `BOOTSTRAPPER_CONFIG_PATH` set | Monitoring source |
|---|---|---|
| old | n/a | app config (unchanged) |
| new | not set | app config fallback (unchanged) |
| new | set, file present | bootstrap config (new behaviour) |
| new | set, file absent | startup error — `LoadAndValidateConfig` fails |

### Step 4 — cleanup (later, non-urgent)

Once all instances are migrated, open a follow-up to remove `token.Config.Monitoring`
and the `ResolveMonitoring` call in the factory.

---

## References

- Prior changelog: `2026-06-24_monitoring_config_in_bootstrap.md`
