# e2e/chaos

Shared helpers for CCIP devenv chaos tests: inject container outages via Pumba, resolve
service container names from `ccv.Cfg`, and run a V3 send + offchain assert pipeline.

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

`RunScenario` injects the outage, sends a V3 message, waits for source commit, asserts
aggregator/indexer state, and optionally confirms execution on the destination.

Callers pass `ccv.Lib` and message fields — the package does not load chains or filter
by family. EVM-only chaos tests can hydrate messages with `HydrateEVMEOADefaultVerifier`.

```go
msg, err := chaos.HydrateEVMEOADefaultVerifier(ctx, lib, src, dst)
require.NoError(t, err)

err = chaos.RunScenario(t, ctx, chaos.ScenarioSpec{
    Lib:      lib,
    Src:      src,
    Dst:      dst,
    Fields:   msg.Fields,
    MsgOpts:  msg.MsgOpts,
    SendArgs: tcapi.SendArgs{},
    Outage:   outageSpec,
    Assert:   tcapi.AssertMessageOptions{ExpectedVerifierResults: 1, Timeout: timeout},
    ConfirmExecOnDest: true,
})
```

Cross-family callers (e.g. Solana devenv) supply their own `Fields` / `MsgOpts` and
use `ExecutorContainersForDest` when multiple executors share the same qualifier.
