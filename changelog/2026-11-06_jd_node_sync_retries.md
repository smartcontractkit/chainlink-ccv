# JD node registration retries and health reporting

## Executive Summary

- `UpdateNode` now returns JD's per-chain `ChainConfigErrors` instead of discarding them.
- A failed on-connect node registration is retried with exponential backoff until it succeeds.
- Verifier and executor `/health` reports `jd.UpdateNode` degraded while the latest registration attempt failed.
- Job processing continues while registration is degraded; the new reporter does not make the process not ready.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `client.Client.UpdateNode` | behavior-changed | `\.UpdateNode\(` | `common/jd/client/client.go` | [#node-sync](#node-sync) |
| `lifecycle.Manager` on-connect hook | behavior-changed | `OnConnectHook:` | `common/jd/lifecycle/manager.go` | [#node-sync](#node-sync) |
| `lifecycle.HookStatus`, `lifecycle.NewHookStatus` | added | `NewHookStatus\(` | `common/jd/lifecycle/hook_status.go` | [#health](#health) |
| `lifecycle.Config.OnConnectHookStatus` | added | `OnConnectHookStatus` | `common/jd/lifecycle/manager.go` | [#health](#health) |
| `bootstrap.ServiceDeps.HealthReporters` | added | `HealthReporters` | `bootstrap/bootstrap.go` | [#health](#health) |

## Breaking Changes

*No breaking changes.*

## Migration Guide

A service started through `bootstrap` should register every `deps.HealthReporters` entry on its application health manager, as `cmd/verifier` and `cmd/executor` now do. Without that registration, a failed JD node sync is only logged.

## Node sync

`Client.UpdateNode` formats `UpdateNodeResponse.ChainConfigErrors` as an error sorted by chain key. `Manager` runs a failed on-connect hook again after 5 seconds, doubling the delay up to 5 minutes, until an attempt succeeds. A new JD connection resets the backoff. The 10-second per-attempt control-plane timeout is unchanged.

## Health

`bootstrap` creates a `HookStatus` named `jd.UpdateNode` when it installs an UpdateNode hook and passes it through `ServiceDeps.HealthReporters`. The reporter always returns ready and returns the last attempt's error from `Degraded()`, so the application health endpoint names a registration failure without taking the service offline.

## References

- Related standalone migration documentation: `docs/migration/evm-cl-to-standalone.md`
