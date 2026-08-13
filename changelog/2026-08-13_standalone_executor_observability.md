# Restore standalone executor destination monitoring and health endpoint

## Executive Summary

- Standalone executors now attach their process-level monitoring to accessor-built destination
  readers and contract transmitters, so OffRamp read latency/failure and unrecoverable transmit
  metrics emit after cutover.
- The standalone executor now serves an HTTP server with a `/health` endpoint backed by the
  coordinator's health report; the verifier's previously hardcoded `:8100` is unchanged in default.
- Both binaries accept `http_listen_port` in the job's app config; the field is omitted from
  marshaled job specs when unset, so CL-mode specs are byte-identical.
- The executor's disabled chainlink-evm balance monitor is now a documented decision: funding the
  generated transmitter key is a runbook step with an external balance alert.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `executor.Factory.Start` | behavior-changed | `func \(f \*Factory\) Start` | `cmd/executor/service.go:106` | [Executor health endpoint](#executor-health-endpoint) |
| `executor.Factory.Stop` | behavior-changed | `func \(f \*Factory\) Stop` | `cmd/executor/service.go:76` | [Executor health endpoint](#executor-health-endpoint) |
| `chainaccess.ExecutorMonitoringSetter` | added | `ExecutorMonitoringSetter\b` | `pkg/chainaccess/interfaces.go:70` | [Executor monitoring wiring](#executor-monitoring-wiring) |
| `destinationreader.EvmDestinationReader.SetExecutorMonitoring` | added | `SetExecutorMonitoring\(` | `integration/pkg/destinationreader/evm_destination_reader.go:50` | [Executor monitoring wiring](#executor-monitoring-wiring) |
| `contracttransmitter.TXMEVMContractTransmitter.SetExecutorMonitoring` | added | `SetExecutorMonitoring\(` | `integration/pkg/contracttransmitter/txm_evm_contract_transmitter.go:64` | [Executor monitoring wiring](#executor-monitoring-wiring) |
| `executor.Configuration.HTTPListenPort` | added | `http_listen_port` | `executor/config.go:81` | [Configurable listen ports](#configurable-listen-ports) |
| `commit.Config.HTTPListenPort` | added | `http_listen_port` | `verifier/pkg/commit/config.go:196` | [Configurable listen ports](#configurable-listen-ports) |

## Breaking Changes

No breaking changes.

## Behavior Changes

### Executor monitoring wiring

The EVM accessor factory constructs destination readers and contract transmitters before the
executor's process-level monitoring exists, so both held a no-op implementation and dropped
`RecordOfframpGetCCVsForMessageLatency`, `IncrementOfframpGetCCVsForMessageFailure`, and
`IncrementUnrecoverableMessageFailure`.

`chainaccess.ExecutorMonitoringSetter` is an optional capability, mirroring
`CriticalSourceInvariantCallbackSetter` for the verifier's source readers. The standalone executor
attaches its real monitoring to every accessor-provided destination reader and contract
transmitter implementing it, before the coordinator starts (`cmd/executor/service.go:158`). The
EVM destination reader and TXM contract transmitter implement it; components without the
capability are unchanged.

### Executor health endpoint

The standalone executor serves `/health` (200 only when every entry in
`Coordinator.HealthReport()` is healthy, 503 naming the failing component otherwise) and a `/`
info endpoint. The server starts after the coordinator and is shut down in `Factory.Stop` before
the coordinator closes. A bind failure is logged and does not fail startup. The verifier's
existing server is unchanged apart from the configurable port.

### Configurable listen ports

Both app configs accept `http_listen_port`. The executor defaults to 8101 (matching the port
devenv already exposes for it) and applies the default in `GetNormalizedConfig`; the verifier
defaults to 8100 and applies it in the service factory. Both validate against negative values. The
TOML tag carries `omitempty`, and the deployment changesets never set the field, so marshaled
CL-mode and standalone job specs are byte-identical to before; the value is only ever present when
an operator or spec author sets it deliberately. In CL mode the field is inert — the Chainlink
node serves its own API.

Probe guidance (which endpoint to use for liveness vs. readiness, and what the bootstrapper's
`/ready` does and does not cover) is in the migration procedure's new "Health and readiness
endpoints" section (`docs/migration/evm-cl-to-standalone.md`).

## Compatibility & Requirements

- No dependency changes.
- Configuration schemas gain one optional key per app; strict app-config decoding accepts specs
  with and without it.
- The balance monitor stays disabled in the standalone EVM chain config; the funding check and
  external alerting expectation are documented in the migration procedure's "Fund the executor"
  step.

## References

- Prior changelog entries: `2026-08-11_cutover_parity_cleanup.md`,
  `2026-08-11_standalone_verifier_observability.md`
