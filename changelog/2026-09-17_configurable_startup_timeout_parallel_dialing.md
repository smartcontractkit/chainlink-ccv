# Configurable startup timeout and parallel per-chain dialing

## Executive Summary

- The bootstrapper's fixed 10-second startup deadline is now configurable via `startup_timeout` in the non-secret bootstrap config, and per-chain accessor dialing in the verifier factories runs in parallel instead of sequentially.
- `verifier.Coordinator.Start` also starts every chain's source reader service in parallel instead of sequentially — this was the phase actually named in the crashloop's error message (`failed to start source reader service for chain X`), and was left sequential by the initial pass at this fix.
- Both changes address crash-looping on boot: startup work grew with the number of configured chains (one EVM runtime dial per chain, all sequential, plus a finalized-block RPC per chain without a `ccv_chain_statuses` row), so the hardcoded 10s was exhausted by the pre-coordinator phase alone once enough chains — or one slow RPC endpoint — were configured. The failing chain named in `context deadline exceeded` errors was whichever map entry came next when the deadline fired, not the culprit.
- Affected: the `bootstrap` package (config surface + `Run`), `bootstrap.AccessorCloserRegistry`, both verifier service factories (`cmd/verifier`), `verifier.Coordinator.Start`, and callers of `chainaccess.Registry.GetAccessor`.
- No breaking changes: `startup_timeout` is optional (default remains 10s) and all public interfaces keep their signatures.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `bootstrap.NonSecretConfig.StartupTimeout` | added | `startup_timeout\|StartupTimeout` | `bootstrap/config.go:315` | [#startup-timeout-config](#startup-timeout-config) |
| `bootstrap.Run` | behavior-changed | `bootstrap\.Run\(` | `bootstrap/bootstrap.go:1086` | [#run-startup-deadline](#run-startup-deadline) |
| `bootstrap.AccessorCloserRegistry.GetAccessor` | behavior-changed | `AccessorCloserRegistry.*GetAccessor\|t\.inner\.GetAccessor` | `bootstrap/accessor_closer_registry.go:33` | [#closer-registry-concurrency](#closer-registry-concurrency) |
| `cmd/verifier.tokenVerifierFactory.Start` | behavior-changed | `sourceReadersForChains\(` | `cmd/verifier/tokenfactory.go:103` | [#parallel-dialing](#parallel-dialing) |
| `cmd/verifier.sourceReadersForChains` | added | `sourceReadersForChains\(` | `cmd/verifier/tokenfactory.go:223` | [#parallel-dialing](#parallel-dialing) |
| `cmd/verifier.factory.Start` (committee verifier) | behavior-changed | `sourceReadersForChains\(` | `cmd/verifier/servicefactory.go:219` | [#parallel-dialing](#parallel-dialing) |
| `chainaccess.Registry.GetAccessor` | behavior-changed | `Not concurrent safe` | `pkg/chainaccess/registry.go:167` | [#registry-concurrency-contract](#registry-concurrency-contract) |
| `verifier.Coordinator.Start` | behavior-changed | `startSourceReaderServices\(` | `verifier/pkg/coordinator.go:345` | [#coordinator-parallel-start](#coordinator-parallel-start) |
| `verifier.startSourceReaderServices` | added | `func startSourceReaderServices` | `verifier/pkg/coordinator.go:364` | [#coordinator-parallel-start](#coordinator-parallel-start) |

## Breaking Changes

No breaking changes.

## New Features / Additions

- **`startup_timeout` bootstrap config field** — optional duration in the non-secret bootstrap config bounding `Run`'s synchronous startup phase. Unset or zero keeps the previous 10s default; negative values are rejected at config load. See [#startup-timeout-config](#startup-timeout-config).

### `startup_timeout` config

Top-level key of the non-secret bootstrap config (the file at `BOOTSTRAPPER_CONFIG_PATH`, default `/etc/config.toml`):

```toml
app_config_mode = "local_app_config"
local_app_config_path = "/etc/app.toml"
startup_timeout = "30s"
```

Decoded into `bootstrap.NonSecretConfig.StartupTimeout` (`time.Duration`). It bounds everything `bootstrap.Run` starts synchronously: keystore/DB/monitoring/JD registration in jd mode; in local mode the entire service start, including per-chain accessor dialing and coordinator source-reader initialization. Note the deadline is a wall-clock bound on one context — total startup work, not any single call.

## Behavior Changes

### `Run` startup deadline

`bootstrap.Run` now derives its startup context deadline from the loaded config (`Config.resolveStartupTimeout()`) instead of the hardcoded `defaultStartupTimeout` (10s, retained as the default). Behavior is identical for deployments that do not set `startup_timeout`.

### Parallel dialing

Both verifier factories (token and committee) previously dialed chains sequentially: `for _, selector := range chainSelectors { deps.Registry.GetAccessor(ctx, selector) ... }`. Each EVM `GetAccessor` runs a full chainlink-evm runtime startup (RPC dial + head tracker), so boot time was the sum of every chain's dial inside one shared deadline. Both factories now share `cmd/verifier.sourceReadersForChains`, which starts one goroutine per chain (each writing to its own result slot, so no lock is needed) and waits. Per-chain failure semantics are unchanged: a chain whose accessor, source reader, or (committee verifier only) instrumentation step fails is logged and skipped; only the absence of every reader is fatal (enforced downstream by `verifier.NewCoordinatorWithDetector`, which rejects "no enabled/initialized chain sources").

`sourceReadersForChains` takes an optional `transform` hook so the committee factory can wrap each reader with monitoring (`instrumentSourceReader`) without duplicating the fan-out/collect logic; the token factory passes `nil`.

### Coordinator parallel start {#coordinator-parallel-start}

`verifier.Coordinator.Start` previously started every chain's source reader service sequentially: `for chainSelector, srs := range vc.sourceReaderServices { srs.Start(ctx) ... }`. This is the phase the crashloop's error message actually names — `sourcereader.Service.Start` calls `initializeStartBlock`, which for any chain without a stored `ccv_chain_statuses` row makes a synchronous finalized-block RPC — so this loop, not just accessor dialing, could exhaust the shared startup deadline on its own. It's now `startSourceReaderServices`, which starts every chain's service in its own goroutine and joins all resulting errors; failure semantics are unchanged (any chain failing to start still fails the whole `Coordinator.Start` call).

### Closer registry concurrency

`bootstrap.AccessorCloserRegistry.GetAccessor` previously held its mutex across the inner `GetAccessor` call, which would have serialized parallel dialing at the wrapper layer. It now locks only around the bookkeeping append, so the inner dial runs unlocked. `CloseAll` therefore requires that no `GetAccessor` is in flight when it runs — already guaranteed by every caller (the service factories finish all dials before returning; `CloseAll` runs after the factory returns).

### Registry concurrency contract

`pkg/chainaccess.registry.GetAccessor`'s "Not concurrent safe" doc comment is replaced with the actual contract: the base registry is safe for concurrent `GetAccessor` (its factory map is immutable after `NewRegistry`) provided the registered family factories are. The EVM factory qualifies — it reads only config maps populated at construction and builds a fresh runtime per call. A new family factory with shared mutable state must synchronize before callers may parallelize `GetAccessor` across chains.

`bootstrap.KeystoreRegistry.GetAccessor` gained the same kind of doc comment: it calls the shared `keystore.Keystore`'s `SetKeystore` concurrently across chains now that dialing is parallel, which is safe because the concrete keystore implementations guard their own state and each accessor's `SetKeystore` only touches that accessor's own fields.

## Examples

```toml
# config.toml — raise the startup budget for a many-chain verifier deployment
app_config_mode = "local_app_config"
local_app_config_path = "/etc/app.toml"
startup_timeout = "30s"
```

## References

- Incident: token verifier `chainlink-ccv-token-verifier-mainnet` crash-looping with `failed to start source reader service for chain <X>: failed to query chain statuses: context deadline exceeded`, where `<X>` varied per restart (random map iteration order over source readers).
