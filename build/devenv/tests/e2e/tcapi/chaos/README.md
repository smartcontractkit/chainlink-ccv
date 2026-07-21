# tcapi/chaos

Standard chaos test helpers for CCIP devenv: inject container outages via Pumba, resolve
service container names from `ccv.Cfg`, and run a V3 send + offchain assert pipeline via
`tcapi.SendV3Message`. Sibling to `tcapi/basic` and `tcapi/token_transfer` — a reusable
test category composing the tcapi primitives.

## Outage injection

```go
cleanup, err := chaos.InjectOutage(ctx, chaos.OutageSpec{
    Duration:      chaos.DefaultOutageDuration,
    Targets:       []string{nginxContainer},
})
t.Cleanup(cleanup)
```

## Container resolution

| Helper | Use for |
|--------|---------|
| `DefaultAggregatorNginx(cfg, committee)` | Global aggregator outage |
| `VerifierContainers(cfg, committee, filter?)` | Verifier outages |
| `ExecutorContainers(cfg, qualifier, nopAliases...)` | Executor outages by qualifier / NOP |
| `ExecutorContainersForDest(cfg, destSelector, qualifier)` | Dest-specific executor (cross-family devenvs) |
| `IndexerContainer(cfg, index)` | Indexer outage |

Container names are normalized from env-out (`Out.ContainerName`, leading `/` stripped).

## RunScenario

`RunScenario` injects the outage, sends a V3 message via `tcapi.SendV3Message`, confirms
the send on source, asserts aggregator/indexer state, and optionally confirms execution on
the destination.

Callers pass `ccv.Lib` and message fields — the package does not filter chains by family.
EVM-only chaos tests hydrate messages with `basic.ResolveEOAReceiverDefaultVerifier`.

```go
receiver, ccvs, executor, err := basic.ResolveEOAReceiverDefaultVerifier(ctx, lib, src, dst)
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
    Outage:   outageSpec,
})
```

`ScenarioSpec` uses flat fields for all send/assert/exec options; only `Outage` is
chaos-specific. Exec timeout falls back to `Assert.Timeout` then
`tcapi.DefaultExecTimeout`.

Cross-family callers (e.g. Solana devenv) supply their own `Fields` / `Opts` and
use `ExecutorContainersForDest` when multiple executors share the same qualifier.
