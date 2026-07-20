# e2e/chaos

Shared helpers for CCIP devenv chaos tests: inject container outages via Pumba, resolve
service container names from `ccv.Cfg`, and run the V3 message lifecycle (send, assert,
optionally confirm execution) via `tcapi.RunV3MessageLifecycle`.

## Outage injection

```go
cleanup, err := chaos.InjectOutage(ctx, chaos.OutageSpec{
    Duration:      chaos.DefaultOutageDuration,
    Targets:       []string{nginxContainer},
    LiteralSingle: true, // aggregator nginx uses an unanchored Pumba target
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

`RunScenario` injects the outage, then runs the standard V3 message lifecycle
(send -> confirm-send-on-source -> offchain assert -> optional confirm-exec-on-dest)
via `tcapi.RunV3MessageLifecycle`.

Callers pass `ccv.Lib` and message fields — the package does not load chains or filter
by family. EVM-only chaos tests hydrate messages with
`basic.ResolveEOAReceiverDefaultVerifier`.

```go
receiver, ccvs, executor, err := basic.ResolveEOAReceiverDefaultVerifier(ctx, lib, src, dst)
require.NoError(t, err)

err = chaos.RunScenario(t, ctx, chaos.ScenarioSpec{
    Lib: lib,
    V3MsgConifg: tcapi.V3MsgConifg{
        Src: src,
        Dst: dst,
        Fields: cciptestinterfaces.MessageFields{Receiver: receiver},
        Opts:   cciptestinterfaces.MessageOptions{FinalityConfig: 1, Executor: executor, CCVs: ccvs},
        SendArgs: tcapi.SendArgs{},
        Assert:   tcapi.AssertMessageOptions{ExpectedVerifierResults: 1, Timeout: timeout},
        ConfirmExec: true,
    },
    Outage: outageSpec,
})
```

`ScenarioSpec` embeds `tcapi.V3MsgConifg`, so all send/assert/exec fields are set
inline; only `Outage` is chaos-specific. When `ExecTimeout` is zero it falls back to
`Assert.Timeout` then `tcapi.DefaultExecTimeout`.

Cross-family callers (e.g. Solana devenv) supply their own `Fields` / `Opts` and
use `ExecutorContainersForDest` when multiple executors share the same qualifier.
