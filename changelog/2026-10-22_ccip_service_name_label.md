# Add `ccip_service_name` to `ccip_service_started`, deprecate `service_name`

## Executive Summary

- Adds a `ccip_service_name` label to `ccip_service_started` (and the shared service metrics) via
  `common/metrics`.
- `service_name` is still emitted, unchanged, so existing alerts and dashboards keep working while
  consumers migrate.
- The old key collides with the OTel resource attribute `service.name`, which telemetry pipelines
  export as `service_name`; on OTLP ingestion the resource value can shadow the per-service value
  (for a Chainlink node: `chainlink`).
- Additive change: nothing breaks. `service_name` is deprecated and will be removed in a follow-up.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `metrics.DeprecatedServiceNameLabel` | deprecated | `DeprecatedServiceNameLabel\|\bccip_service_started\{[^}]*\bservice_name\b` | `common/metrics/service.go:23` | [#service_name-deprecated](#service_name-deprecated) |
| `ccip_service_started` label `ccip_service_name` | added | `ccip_service_started` | `common/metrics/service.go:21` | [#new-label](#new-label) |

## New Features / Additions

### New label

- **`ccip_service_name`** — the per-service identity on `ccip_service_started`, e.g.
  `ccip_service_name="committee_verifier"`. Emitted by every service that embeds
  `common/metrics.ServiceMetrics` (aggregator, indexer, committee verifier, token verifier,
  executor).
- Unlike `service_name`, no standard OTel resource attribute normalises to this key, so it cannot
  be shadowed by the process-level `service.name`. See `common/metrics/service.go:21`.

## Deprecations

### service_name deprecated

- **`metrics.DeprecatedServiceNameLabel` / `service_name` on `ccip_service_started`** — deprecated
  in favour of `ccip_service_name`.
- Still emitted for backward compatibility. Do not use it in new rules: on pipelines that convert
  resource attributes to Prometheus labels (`resource_to_telemetry_conversion`, vmagent's
  `-opentelemetry.usePrometheusNaming`), the resource `service.name` wins the label name, so the
  value is the process name rather than the service name. On a Chainlink node that is `chainlink`
  for both the committee verifier and the executor.
- Planned removal: after all alerts and dashboards consume `ccip_service_name`. The removal will be
  a separate breaking change.

## Migration Guide

1. Point new and updated queries at `ccip_service_name`:

```promql
# Before
ccip_service_started{service_name=~".*(committee_verifier|executor)"}

# After
ccip_service_started{ccip_service_name=~"^(committee_verifier|executor)$"}
```

2. During a mixed-version rollout, a pod either has the new label or does not. Until every service
   is redeployed, a query that must cover both can union the two:

```promql
ccip_service_started{ccip_service_name=~"^(committee_verifier|executor)$"}
or
ccip_service_started{service_name=~"^(committee_verifier|executor)$"}
```

3. Once `ccip_service_name` is available everywhere, remove `service_name` from queries. The
   follow-up release drops the label and `DeprecatedServiceNameLabel`.

## Compatibility & Requirements

- Rolling upgrade: safe. Old binaries emit only `service_name`; new binaries emit both.
- The label is additive, so time series cardinality is unchanged. Existing rules on other metrics
  that use `service_name` (for example `aggregator_*` / `indexer_*` health rules) are unaffected:
  this change only touches the shared service-level gauge.
- `ccip_chain_healthy` keeps its `service` label and additionally gains both service labels via the
  shared labeler.

## References

- Related: O11Y-2408 vmagent chart `0.27.1 → 0.48.0` rollout (2026-09-30), after which
  `service_name` resolved to the OTel resource value on node-hosted services.
- Prior entry: `changelog/2026-09-16_devenv_service_identity.md` (resource `service.name` setup).
