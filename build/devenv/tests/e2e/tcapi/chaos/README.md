# tcapi/chaos

Standard chaos test helpers for CCIP devenv: inject container outages and network latency via Pumba, resolve
service container names from `ccv.Cfg`, and run a V3 send + offchain assert pipeline via
`tcapi.SendV3Message`. Sibling to `tcapi/basic` and `tcapi/token_transfer` — a reusable
test category composing the tcapi primitives.

## Container resolution

| Helper | Use for |
|--------|---------|
| `DefaultAggregatorNginx(cfg, committee)` | Global aggregator outage |
| `VerifierContainers(cfg, committee, filter?)` | Verifier outages |
| `ExecutorContainers(cfg, qualifier, nopAliases...)` | Executor outages by qualifier / NOP |
| `ExecutorContainersForDest(cfg, destSelector, qualifier)` | Dest-specific executor (cross-family devenvs) |
| `IndexerContainer(cfg, index)` | Indexer outage |
| `BlockchainContainer(cfg, index)` | Blockchain RPC outage by array index |
| `BlockchainContainerForSelector(cfg, selector)` | Blockchain RPC outage by chain selector |
| `VerifierDBContainers(cfg, committee, filter?)` | Verifier Postgres outage |
| `BlockchainInputForSelector(cfg, selector)` | Reading how a node was launched (e.g. anvil `-b`) |

Container names are normalized from env-out (`Out.ContainerName`, leading `/` stripped).

A verifier's Postgres container hosts both the verifier database and that verifier's bootstrap
database, so `VerifierDBContainers` targets chain statuses, the job queues, the keystore and the job
store at once.

## Durability tests

`tests/e2e/chaos_durability_test.go` holds the restart-recovery coverage. Each test kills or isolates
something holding state and asserts a message still gets delivered:

| Test | State at risk | Recovery under test |
|------|---------------|---------------------|
| `TestChaos_ExecutorRestartWithInFlightTransaction` | TXM v2 in-flight transactions (memory only) | Nonce-gap detection in the EVM accessor |
| `TestChaos_VerifierRestartWithMessageOnChain` | `ccv_task_verifier_jobs` locks | Stale-job reclaim after `taskQueueLockDuration` |
| `TestChaos_VerifierResumesFromCheckpoint` | `ccv_chain_statuses` scan position | Resuming from the checkpoint rather than the fallback lookback |
| `TestChaos_VerifierDatabaseOutage` | All of the above, plus the bootstrap keystore | Source reader retrying rather than dropping tasks |

They need anvil-backed chains and skip otherwise: two of them drive block production directly via
`cciptestinterfaces.MineHoldableChain` (`HoldMining` / `ResumeMining` / `MineBlocks`), which is how a
transaction gets held in the mempool and how the head gets moved past a lookback window without
also moving chain time.

## Limitations & TODOs

### RPC outage (blackout) — TODO CCIP-12571

Stopping an EVM blockchain RPC container via Pumba `stop --restart` leaves the
test harness's `ethclient.Client` holding a dead connection. The go-ethereum
`rpc.Client` (HTTP transport) has no reconnection logic, and `CCIP17EVM`
(`evm/impl.go`) caches the client and all `abigen`-generated contract bindings
(`offRamp`, `onRamp`, `feeQuoter`) at env-setup time. After the container
restarts, the `eventPoller` retries `BlockNumber` every 1s but the stale
`http.Transport` connection pool (worse on macOS) keeps failing, so
`ConfirmExecOnDest` hangs until the test timeout.

Until the EVM devenv implements RPC reconnection (re-dial + re-bind on
persistent failure), RPC **outage** tests are skipped. The container resolvers
(`BlockchainContainer`, `BlockchainContainerForSelector`) and `OutageSpec` are
already in place for the future test. Network **latency** injection (`netem
delay`) works today because the container stays running and connections
survive. Solana devenv can use `OutageSpec` against its RPC node today since
Solana clients reconnect natively.

## RunScenario

`RunScenario` is the single entry point for chaos tests. It injects the chaos
fault (latency or outage), sends a V3 message via `tcapi.SendV3Message`,
confirms the send on source, asserts aggregator/indexer state, and optionally
confirms execution on the destination. Callers pass `ccv.Lib` and message
fields — the package does not filter chains by family.

```go
receiver, ccvs, executor, err := tcapi.ResolveV3SendAddresses(ctx, lib, src, dst)
require.NoError(t, err)

err = chaos.RunScenario(t, ctx, chaos.ScenarioSpec{
    Lib:      lib,
    Src:      src,
    Dst:      dst,
    Fields:   cciptestinterfaces.MessageFields{Receiver: receiver},
    Opts:     cciptestinterfaces.MessageOptions{FinalityConfig: 1, Executor: executor, CCVs: ccvs},
    SendArgs: tcapi.SendArgs{},
    Assert:   tcapi.AssertMessageOptions{ExpectedVerifierResults: 1, Timeout: timeout},
    ConfirmExecOnDest: true,
    Outage:   &outageSpec,
})
```

`ScenarioSpec` uses flat fields for all send/assert/exec options. `Outage`
(`*OutageSpec`) and `Latency` (`*LatencySpec`) are chaos-specific; pass `nil`
for the unused mode. `Latency` takes precedence over `Outage` when both are
non-nil. Exec timeout falls back to `Assert.Timeout` then
`tcapi.DefaultExecTimeout`.

Cross-family callers (e.g. Solana devenv) supply their own `Fields` / `Opts` and
use `ExecutorContainersForDest` when multiple executors share the same qualifier.
