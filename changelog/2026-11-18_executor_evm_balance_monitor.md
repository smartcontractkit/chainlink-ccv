# Standalone executor EVM balance monitoring

## Executive Summary

- Standalone EVM destination executors now run chainlink-evm's balance monitor by default.
- The monitor uses the same key-name-restricted `ChainStore` as TXM, so it tracks the executor's generated transmitter key without exposing other keys.
- Balances are read at startup and on sampled new longest-chain notifications, exporting the existing OTel `node_balance` gauge with `account`, `chainID`, and `chainFamily = "EVM"` attributes.
- Converted Chainlink node configs retain `BalanceMonitor.Enabled`; an explicit `false` opts out. Configured ERC-20 fee-token monitoring is supported; decimal initialization is preflighted and cached for lifecycle safety across downstream chainlink-evm versions.
- Continuous metric collection does not create low-balance alerts; alerts should cover missing or stale series as well as thresholds.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.standaloneChain.startBalanceMonitorLocked` | added | `startBalanceMonitorLocked` | `integration/pkg/accessors/evm/standalone_chain.go:366` | [#executor-monitor-lifecycle](#executor-monitor-lifecycle) |
| `evm.newERC20DecimalsClient` | added | `newERC20DecimalsClient` | `integration/pkg/accessors/evm/balance_monitor.go:29` | [#executor-monitor-lifecycle](#executor-monitor-lifecycle) |
| `evm.accessor.Degraded` | behavior-changed | `BalanceMonitor|balance monitor` | `integration/pkg/accessors/evm/factory.go:535` | [#executor-monitor-lifecycle](#executor-monitor-lifecycle) |
| `executor.accessorsHealthReporter` | added | `executor.Accessors` | `cmd/executor/service.go:133` | [#executor-monitor-lifecycle](#executor-monitor-lifecycle) |
| `evmconfig.standaloneSettings` | behavior-changed | `BalanceMonitor.Enabled` | `integration/pkg/accessors/evmconfig/chainlink_config.go:88` | [#configuration](#configuration) |
| chainlink-evm and chainlink-common versions | behavior-changed | `chainlink-evm|chainlink-common` | `go.mod` | [#compatibility--requirements](#compatibility--requirements) |

## Breaking Changes

*No breaking changes.* Existing executor and keystore APIs are unchanged.

## New Features / Additions

### Executor monitor lifecycle

`standaloneChain.NewContractTransmitter` starts chainlink-evm's `monitor.BalanceMonitor` for destination executors after the restricted transmitter `ChainStore` is available. The fee-quoter-only TXM path does not start it, and source-only accessors still start no signing services. The constructor receives `BalanceMonitor.ERC20TokenAddress` using the same native-versus-token selection as core's `legacyevm` chain.

The monitor receives the existing multi-node chain client and head broadcaster. Upstream `Start` performs an immediate balance read, so standalone performs construction and startup in a tracked background goroutine. Only a successful start subscribes to heads; the subscription's current head is replayed so no balance update waits for the next block. Close cancels startup, waits for it, unsubscribes, and closes only a monitor that reached Started, before closing the head broadcaster and client.

chainlink-evm reads ERC-20 decimals during `Start`. If that call fails, upstream's outer service enters StartFailed without exposing the cleanup operation needed to stop its already-constructed worker. `newERC20DecimalsClient` therefore resolves decimals against the real client before construction and supplies a narrow client decorator that answers only the exact latest-block `decimals()` request from cache. Every other RPC, including `balanceOf`, delegates unchanged. A failed preflight constructs no monitor, never subscribes, and reports degraded health without affecting transmission.

`standaloneChain.Degraded` exposes monitor initialization failures through `accessor.Degraded`. The executor retains each usable accessor's documented degradation hook and reports live failures through `executor.Accessors`, making `/health` degraded while remaining HTTP 200. This deliberately includes existing signing-key, fee-quoter, and chain-default conditions, not just monitor failures. Aggregate errors are sorted by chain selector and prefixed with `Chain[<selector>]`. Upstream per-read balance and key failures remain log errors rather than lifecycle errors, so metric alerts must also detect a missing or stale series.

### Configuration

`BalanceMonitor.Enabled` is removed from the forced-false `standaloneSettings` overrides. Chainlink's embedded fallback enables the monitor by default, and a converted Chainlink node setting is preserved. The focused standalone EVM config schema is unchanged and has no new setting. The prod-testnet DON's explicit enabled settings on Polygon Amoy (80002) and chain 157 therefore carry over without warnings.

The metric records an approximate balance as a `float64`, labeled with the public transmitter account and numeric EVM chain ID. `/transmitter-keys` remains an independent on-demand UI with exact native base-unit amounts.

## Compatibility & Requirements

- `chainlink-evm` and its `gethwrappers` module move to `d1ee27b0b587`, whose four-argument `NewBalanceMonitor` matches core's selected API and scales configured ERC-20 balances using the token's decimals. Its Go 1.26.6 requirement preserves this repository's Go 1.26.10 baseline; the cached decimals lookup protects both the standalone and core-selected lifecycles.
- `chainlink-common` moves to `1d3a14a9b049`, as required by the chainlink-evm bump. Direct, transitive, and tool modules are tidied consistently.
- The chainlink-evm embedded defaults are refreshed, including Tempo's ERC-20 pathUSD monitoring and the Ethereum Mainnet/Sepolia `LimitTransfer = 200_000` change.
- A native chain makes one `BalanceAt` request per enabled transmitter key at startup and per sampled head. An ERC-20 chain additionally makes one preflight decimals request; subsequent startup decimal lookups use the cached response. `HeadTracker.SamplingInterval` caps head-driven reads (5s in the CCIP fallback and 1s on a few chains), and upstream coalesces queued wakeups.
- Beholder must be enabled to export the OTel `node_balance` gauge. Alert configuration and ownership remain outside the executor.

## References

- Repository chainlink-evm selection: `d1ee27b0b5875adb8eca1e0da05926f7eb1f6e1f`.
- Chainlink-core chainlink-evm selection (`e640e1c12078eef3838b151ac8af7abc707824a6`) has the same `balance.go` implementation.
- Prior lifecycle decision: `changelog/2026-08-13_standalone_executor_observability.md`.
- On-demand transmitter balance UI: `changelog/2026-11-10_admin_job_spec_transmitter_balances.md`.
