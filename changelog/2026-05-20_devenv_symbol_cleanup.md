# devenv: symbol cleanup and sub-package extraction

## Summary

Removes several public symbols from the root `ccv` devenv package by moving them into focused sub-packages (`timing`, `chainreg`, `deploy`). Also deletes the `PhasedSetup` struct, removes the package-level `Plog` logger, and adds a `LogSetter` interface to the phased runtime so components can receive the runtime logger without package-level state.

---

## Breaking change: `ccv.Plog` removed

The package-level `zerolog.Logger` var `Plog` (`build/devenv/log.go`) has been deleted. Any caller seeding a logger from `ccv.Plog` must switch to constructing their own logger.

| What | Before | After |
|------|--------|-------|
| Package-level logger | `ccv.Plog` | Deleted — construct directly |

---

## Breaking change: `ccv.TimeTracker` / `ccv.NewTimeTracker` moved

`TimeTracker` and its constructor have moved to the new `build/devenv/timing` sub-package. The constructor is also renamed.

| What | Before | After |
|------|--------|-------|
| Type | `ccv.TimeTracker` | `timing.TimeTracker` |
| Constructor | `ccv.NewTimeTracker(l)` | `timing.New(l)` |
| Import | `github.com/.../build/devenv` | `github.com/.../build/devenv/timing` |

Before:
```go
import ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"

t := ccv.NewTimeTracker(logger)
```

After:
```go
import "github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"

t := timing.New(logger)
```

**Behavioral note**: `TimeTracker.Print()` now uses lowercase structured log field keys (`"tag"`, `"duration"`) instead of the previous title-case keys (`"Tag"`, `"Duration"`). Log consumers parsing structured fields need updating.

---

## Breaking change: `ccv.NewProductConfigurationFromNetwork` moved

Moved to the `chainreg` sub-package (no signature change).

| What | Before | After |
|------|--------|-------|
| Function | `ccv.NewProductConfigurationFromNetwork(typ)` | `chainreg.NewProductConfigurationFromNetwork(typ)` |
| Import | `github.com/.../build/devenv` | `github.com/.../build/devenv/chainreg` |

---

## Breaking change: `ccv.BuildEnvironmentTopology` moved and signature changed

Moved to the `deploy` sub-package. The signature changed from accepting `*Cfg` to accepting the topology and verifiers directly.

| What | Before | After |
|------|--------|-------|
| Package | `ccv` | `deploy` |
| First arg | `in *Cfg` | `topology *ccvdeployment.EnvironmentTopology` |
| New arg | — | `verifiers []*committeeverifier.Input` |

Before:
```go
topology := ccv.BuildEnvironmentTopology(in, e)
```

After:
```go
import ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"

topology := ccdeploy.BuildEnvironmentTopology(in.EnvironmentTopology, in.Verifier, e)
```

---

## Breaking change: `ccv.PhasedSetup` struct deleted

The `PhasedSetup` struct exported from `build/devenv/environment_phased.go` has been removed. Its fields are now passed as individual arguments to `runPhasedEnvironmentFinish` (unexported). No external callers should have held a `*PhasedSetup` directly, but any that did must be updated.

---

## New: `devenvruntime.LogSetter` interface

Components in the phased runtime may now implement `LogSetter` to receive the runtime's `zerolog.Logger` before any phase method is called. The runtime injects the logger automatically after component instantiation.

```go
// Optional — implement to receive the runtime logger.
type LogSetter interface {
    SetLogger(lggr zerolog.Logger)
}

// Example component implementation:
func (c *myComponent) SetLogger(lggr zerolog.Logger) {
    c.lggr = lggr.With().Str("component", "my_component").Logger()
}
```

---

## Bug fixes

- **`enrichEnvironmentTopology`**: Added nil guard for `NOPTopology`; previously would panic on topologies without a committee section.
- **`legacy_component RunPhase4`**: Required phase output keys (`_ds`, `_time_track`, `_blockchain_outputs`, `_selectors`) now return errors if missing rather than silently using zero values that would cause downstream panics.
