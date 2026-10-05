# Devenv observability reports true service identity

## Summary

- All bootstrap services (verifiers, executors, token verifiers) now set `service.name` and `service.instance.id` in the OTel resource attributes of their generated configs. Grafana and Loki show one stream per service and per container.
- The aggregator and the indexer now stream their application logs to Loki through the beholder logger. Before, they exported metrics and traces only, and their log panels stayed empty.
- The chainlink-common dependency was updated to `v0.11.2-0.20260915214759-02f2214d5823`. The old version dropped custom resource attributes in `beholder`, so Loki labeled the CCV services as `unknown_service:<binary>`. Chainlink-common PR #2269 ("fix(beholder): preserve custom resource attributes") fixes the merge order.

## Service identity in generated configs

- `services.TelemetryAttrs` (`build/devenv/services/common.go`) copies the shared telemetry attributes and adds `service.name` for the service type and `service.instance.id` for the container name. The fresh map prevents per-service writes from changing the shared config.
- The committee verifier, executor, and token verifier components inject these attributes into each bootstrap Monitoring config.
- The committee verifier component applies the verifier defaults before it builds the attributes. A verifier without an explicit `container_name` still gets the default name as its `service.instance.id`.
- The token verifier component now reads its Monitoring config from the observability phase output, not from the environment topology. This matches the other bootstrap services.

## Aggregator and indexer stream logs

- Both mains convert `Monitoring.Beholder.TelemetryAttributes` into `beholder.Config.ResourceAttributes` before `InitMonitoring`.
- Both mains replace the application logger with `logging.InitLogger` plus `logging.WithService` when beholder is enabled. Logs now reach Loki with `service.name` set.
- The aggregator template sets `"service.name" = "aggregator"`. `GenerateConfigs` adds `"service.instance.id"` per aggregator from its instance name, so each aggregator container gets its own Loki stream.
- The indexer main adds `"service.name" = "indexer"` when the config does not set one. The default indexer env config carries only `ccip_env`, so without this fallback Loki would show `unknown_service:indexer`.
- The aggregator main fixes a small bug: an invalid `LOG_LEVEL` env var now resets the level string to `"info"` too. Before, the zap level fell back but the string kept the invalid value.

## Dependency update

- chainlink-common: `v0.11.2-0.20260715145851-8219609496a4` → `v0.11.2-0.20260915214759-02f2214d5823`. The new version keeps custom resource attributes. Without it, the OTel SDK default resource overwrites `service.name`, and Loki shows `unknown_service:<binary>`.
- The new common requires otel v1.46.0. The orchestrator module (`build/devenv`) upgrades otelzap to v0.20.1 and wasp to v1.53.0 for compatibility.
- The root, `build/devenv`, `build/devenv/fakes`, and `indexer/cmd/oapigen` go.mod files are updated together. A repo that pins chainlink-ccv must update its pin and run tidy.

## Validation

- Devenv started with the changes. Loki `service_name` label values: `aggregator`, `executor`, `indexer`, `token-verifier`, `verifier`. No `unknown_service:*` entries remain.
- `service_instance_id` label values distinguish containers, for example `solana-verifier-1` and `solana-verifier-2`.
- Known limitation: the EVM committee verifier logs its steady-state flow at DEBUG level only. The streaming filter defaults to INFO. Set `LogStreamingLevel = "debug"` in the env observability block on the chainlink-ccip-solana side so these logs pass the filter.
- The OTLP collector starts about two minutes after the services. Logs from that window are dropped after retry exhaustion.

## References

- Branch: `jh/fix-obs-logs`
- PR: #1452
- chainlink-common fix: PR #2269, commit `f969f7a6`
