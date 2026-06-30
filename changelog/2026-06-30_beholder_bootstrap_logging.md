# Beholder logging initialized by bootstrap

## Executive Summary

- Bootstrap now owns Beholder setup and logger construction for bootstrapped
  services. `NewBootstrapper` reads monitoring from the bootstrap config, calls
  `monitoring.SetupBeholder`, initializes the service logger, and passes it
  through `ServiceDeps.Logger`.
- Service factories now declare their OpenTelemetry histogram views through
  `MetricViews() []sdkmetric.View`, so bootstrap can create the Beholder client
  with the complete view set before any service monitoring code starts.
- Beholder log streaming is configured from bootstrap monitoring config through
  `common/monitoring/logging.InitLogger`, which combines the normal zap core with
  an optional Beholder OTEL zap core.
- Affects: `bootstrap.ServiceFactory`, `bootstrap.NewBootstrapper`,
  `bootstrap.ServiceDeps.Logger`, committee verifier factory, token verifier
  factory, executor factory, and any tests or local factories implementing
  `bootstrap.ServiceFactory`.
- Breaking: every `bootstrap.ServiceFactory` implementation must add
  `MetricViews() []sdkmetric.View`. Bootstrapped services should use
  `deps.Logger`; bootstrap now controls logger construction.


## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `bootstrap.ServiceFactory.MetricViews` | added | `MetricViews() []sdkmetric.View` | `bootstrap/bootstrap.go:60` | [#servicefactory-metricviews-added](#servicefactory-metricviews-added) |
| `bootstrap.NewBootstrapper` | changed | `func NewBootstrapper(` | `bootstrap/bootstrap.go:145` | [#bootstrap-initializes-beholder-and-logger](#bootstrap-initializes-beholder-and-logger) |
| `bootstrap.Bootstrapper.lggr` | changed | `lggr logger.Logger` | `bootstrap/bootstrap.go:123` | [#bootstrap-owns-the-service-logger](#bootstrap-owns-the-service-logger) |
| `bootstrap.ServiceDeps.Logger` | source changed | `Logger logger.Logger` | `bootstrap/bootstrap.go:45` | [#bootstrap-owns-the-service-logger](#bootstrap-owns-the-service-logger) |
| `monitoring.SetupBeholder` | added | `func SetupBeholder` | `common/monitoring/setup.go` | [#bootstrap-initializes-beholder-and-logger](#bootstrap-initializes-beholder-and-logger) |
| `logging.InitLogger` | added | `func InitLogger` | `common/monitoring/logging/logging.go:16` | [#beholder-log-streaming](#beholder-log-streaming) |
| `cmd/verifier.factory.MetricViews` | added | `func (f *factory) MetricViews` | `cmd/verifier/servicefactory.go:387` | [#servicefactory-metricviews-added](#servicefactory-metricviews-added) |
| `cmd/executor.Factory.MetricViews` | added | `func (f *Factory) MetricViews` | `cmd/executor/service.go:218` | [#servicefactory-metricviews-added](#servicefactory-metricviews-added) |
| `tokenVerifierFactory.MetricViews` | added | `func (tvf *tokenVerifierFactory) MetricViews` | `cmd/verifier/token/main.go:246` | [#servicefactory-metricviews-added](#servicefactory-metricviews-added) |

## Breaking Changes

### ServiceFactory MetricViews added

- **What changed:** `bootstrap.ServiceFactory` now requires
  `MetricViews() []sdkmetric.View`.
- **Before:** service-specific monitoring setup owned its Beholder metric view
  list locally.
- **After:** bootstrap asks the service factory for its metric views before
  startup and passes them into `monitoring.SetupBeholder`.
- **Why:** the Beholder client must be created with all histogram views up front;
  bootstrap is now the single place that initializes Beholder for bootstrapped
  services.
- **Who is affected:** any production, integration, test, or local
  `bootstrap.ServiceFactory` implementation. Code will not compile until it adds
  the method.

### Bootstrap owns the service logger

- **What changed:** bootstrap initializes `Bootstrapper.lggr` during
  `NewBootstrapper` using bootstrap monitoring config and
  `logging.InitLogger`.
- **Before:** logging was initialized closer to each service, and Beholder log
  streaming setup could be duplicated or service-specific.
- **After:** bootstrapped services receive the initialized logger through
  `ServiceDeps.Logger`. Services should use that logger instead of constructing a
  separate root logger for normal runtime logs.
- **Why:** Beholder log streaming must share the same bootstrap-owned monitoring
  configuration and lifecycle as metric/tracing setup.
- **Who is affected:** services or tests that expected to construct the root
  runtime logger outside bootstrap.

## Migration Guide

1. Add `MetricViews() []sdkmetric.View` to every `bootstrap.ServiceFactory`
   implementation.

   ```go
   func (f *Factory) MetricViews() []sdkmetric.View {
       return monitoring.MetricViews()
   }
   ```

2. For factories with no service-specific views, return empty array.

   ```go
   func (f *Factory) MetricViews() []sdkmetric.View {
       return []sdkmetric.View{}
   }
   ```

3. Use `deps.Logger` inside `Start` and store it on the factory if `Stop` needs
   to log.

   ```go
   func (f *Factory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
       f.lggr = deps.Logger
       // ...
   }
   ```

4. Keep Beholder config in the bootstrap `[monitoring]` section. Do not re-create
   a separate Beholder client in service startup paths for bootstrapped services.
   This behaviour is still possible, but discouraged.

## New Features / Additions

### Bootstrap initializes Beholder and logger

`NewBootstrapper` now resolves monitoring config from `bootstrap.Config`, calls
`monitoring.SetupBeholder(mon, fac.MetricViews())`, and initializes the named
logger with `logging.InitLogger(b.name, b.logLevel, mon.Beholder)`.

Static TOML mode and JD mode both use the same bootstrap-owned logger path.

### Beholder log streaming

`common/monitoring/logging.InitLogger` creates the base logger core and, when
`LogStreamingEnabled` is set, adds an OTEL zap core backed by
`beholder.GetLogger()`. If `LogStreamingLevel` is unset, it defaults to `info`.

### ServiceFactory MetricViews

`bootstrap.ServiceFactory` exposes metric views so bootstrap can initialize the
global Beholder client before service monitoring is constructed.

## Compatibility & Requirements

- **Compile-time break:** service factories without `MetricViews` no longer
  implement `bootstrap.ServiceFactory`.
- **Runtime ordering:** Beholder setup now happens during `NewBootstrapper`. Any
  startup failure in Beholder setup or logger construction prevents bootstrapper
  creation.
- **Logger source:** bootstrapped services should treat `ServiceDeps.Logger` as
  the runtime logger source of truth.
- **Monitoring config source:** Beholder settings continue to come from the
  bootstrap monitoring config introduced in
  `2026-06-24_monitoring_config_in_bootstrap.md`.

## References

- Prior changelog entry this builds on:
  `2026-06-24_monitoring_config_in_bootstrap.md`
- Related implementation areas: `bootstrap/bootstrap.go`,
  `common/monitoring/setup.go`, `common/monitoring/logging/logging.go`,
  `cmd/verifier/servicefactory.go`, `cmd/verifier/token/main.go`,
  `cmd/executor/service.go`
