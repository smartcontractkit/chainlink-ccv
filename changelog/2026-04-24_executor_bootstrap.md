# Executor bootstrap refactor

## Summary

The standalone executor now starts via `bootstrap.Run`, the same lifecycle
manager used by all other CCV services.  The `main.go` is now minimal
boilerplate; all executor wiring lives in `cmd/executor/service.go`.

Two bugs discovered during the migration are also fixed (see below).

---

## Breaking change: update your `main.go`

The old `main.go` was ~230 lines: inline logger init, pyroscope, beholder/OTEL
setup, manual signal handling, 30 s shutdown, and all executor coordinator
wiring in one flat function.

Responsibilities are now split:

| What | Where |
|------|-------|
| Config path resolution + process entry point | `main.go` (~30 lines) |
| Signal handling, startup/shutdown timeouts, health server | `bootstrap.Run` |
| Executor wiring (logger, accessors, coordinator, etc.) | `cmd/executor/service.go` (`Factory.Start` / `Factory.Stop`) |

`main.go` is now minimal boilerplate intended for copy-paste into new binaries:

```go
func main() {
    configPath := executorsvc.DefaultConfigFile
    if len(os.Args) > 1 { configPath = os.Args[1] }
    if v := os.Getenv(configPathEnvVar); v != "" { configPath = v }

    err := bootstrap.Run(
        "Executor",
        cmdexecutor.NewFactory(),
        bootstrap.WithTOMLAppConfig(configPath),
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to run executor: %v\n", err)
        os.Exit(1)
    }
}
```

Full reference: `cmd/executor/standalone/main.go`.

### Required imports

```go
import (
    "github.com/smartcontractkit/chainlink-ccv/bootstrap"
    cmdexecutor "github.com/smartcontractkit/chainlink-ccv/cmd/executor"
    executorsvc  "github.com/smartcontractkit/chainlink-ccv/executor"
    _ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm driver
)
```

The EVM blank import registers the accessor driver and must remain in the
binary; the executor logic no longer imports it internally.

---

## Bug fixes

### `bootstrap.Stop` nil panic (bootstrapper without JD)

When using `bootstrap.WithTOMLAppConfig` (no JD), `Stop` would panic on nil
`lifecycleManager` and `infoServer`. Nil guards were added.

### `EVMContractTransmitter` stored startup context

`EVMContractTransmitterFromRPC` stored the `ctx` passed at construction time
and reused it inside `GetTransactOpts` for every `PendingNonceAt` /
`SuggestGasPrice` call.

`bootstrap.Run` passes a 10-second startup context into `fac.Start`, which
flows into `GetAccessor` and into the transmitter. After 10 seconds all
transaction submissions silently failed with `context deadline exceeded`.

Fix: context is no longer stored; `ConvertAndWriteMessageToChain` passes its
own per-call context through to `GetTransactOpts`.

---

## Recommended additions

- **Timeout table**: document the default bootstrap timeouts
  (`defaultStartupTimeout = 10 s`, `defaultShutdownTimeout = 10 s`) so
  operator-authored service factories know they must complete startup within
  that window. Long-running setup (DB migrations, RPC dial) should use
  `context.Background()` internally rather than the passed-in context.

- **Context contract for `ServiceFactory.Start`**: the context passed to
  `Start` expires at the end of startup; it must not be stored for use after
  `Start` returns. Long-lived operations need their own context derived from
  `context.Background()` or a `Start`/`Stop` lifecycle pattern.

- **Test coverage gap**: the context-storage bug was not caught by unit tests
  because tests don't run long enough to hit the deadline. An integration test
  that asserts `ConvertAndWriteMessageToChain` succeeds >10 s after startup
  would have caught this.
