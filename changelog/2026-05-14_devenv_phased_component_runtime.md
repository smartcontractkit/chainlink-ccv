# Devenv phased component runtime

## Summary

Extracts the devenv startup sequence into a 4-phase component registry. Each
phase component now returns declarative side-effect requests (`Effect`) that the
runtime executes centrally. The `ImplFactory` type was moved into its own
package to eliminate import cycles between components and the top-level `ccv`
package.

---

## Breaking change: `ImplFactory` moved to `chainimpl` package

`ImplFactory`, `RegisterImplFactory`, `GetImplFactory`, and
`GetAllImplFactories` were defined in the `ccv` package (`chain_impl_factory.go`,
now deleted). They live in `build/devenv/chainimpl/factory.go`.

| What | Before | After |
|------|--------|-------|
| Package | `ccv` | `chainimpl` |
| Import | `build/devenv` | `build/devenv/chainimpl` |
| Symbols | `ccv.ImplFactory`, `ccv.RegisterImplFactory`, `ccv.GetImplFactory`, `ccv.GetAllImplFactories` | `chainimpl.ImplFactory`, `chainimpl.RegisterImplFactory`, `chainimpl.GetImplFactory`, `chainimpl.GetAllImplFactories` |

Before:
```go
import ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"

ccv.RegisterImplFactory(chainsel.FamilyEVM, &myFactory{})
fac, err := ccv.GetImplFactory(family)
```

After:
```go
import "github.com/smartcontractkit/chainlink-ccv/build/devenv/chainimpl"

chainimpl.RegisterImplFactory(chainsel.FamilyEVM, &myFactory{})
fac, err := chainimpl.GetImplFactory(family)
```

---

## Breaking change: `ImplFactory.New()` dropped `cfg *Cfg`

The `*Cfg` argument has been removed from the `ImplFactory.New` method.

| What | Before | After |
|------|--------|-------|
| `New` signature | `New(ctx, cfg *Cfg, lggr, env, bc)` | `New(ctx, lggr, env, bc)` |

Before:
```go
func (f *myFactory) New(
    ctx context.Context,
    cfg *ccv.Cfg,
    lggr zerolog.Logger,
    env *deployment.Environment,
    bc *blockchain.Input,
) (cciptestinterfaces.CCIP17, error)
```

After:
```go
func (f *myFactory) New(
    ctx context.Context,
    lggr zerolog.Logger,
    env *deployment.Environment,
    bc *blockchain.Input,
) (cciptestinterfaces.CCIP17, error)
```

---

## Breaking change: `NewEnvironmentWithRegistry` gained `EffectExecutor` parameter

An `EffectExecutor` argument was inserted between the registry and logger. Pass
`nil` to keep the previous no-op behaviour.

Before:
```go
devenvruntime.NewEnvironmentWithRegistry(ctx, rawConfig, registry, logger)
```

After:
```go
devenvruntime.NewEnvironmentWithRegistry(ctx, rawConfig, registry, nil, logger)
```

---

## Breaking change: `PhaseNComponent` interfaces return `[]Effect`

All four phase interfaces now return a `[]Effect` slice as the second return
value. Components that emit no effects should return `nil`.

| Interface | Before | After |
|-----------|--------|-------|
| `Phase1Component.RunPhase1` | `(map[string]any, error)` | `(map[string]any, []Effect, error)` |
| `Phase2Component.RunPhase2` | `(map[string]any, error)` | `(map[string]any, []Effect, error)` |
| `Phase3Component.RunPhase3` | `(map[string]any, error)` | `(map[string]any, []Effect, error)` |
| `Phase4Component.RunPhase4` | `(map[string]any, error)` | `(map[string]any, []Effect, error)` |

Before:
```go
func (c *myComp) RunPhase3(
    ctx context.Context, globalConfig, componentConfig map[string]any, prior map[string]any,
) (map[string]any, error) {
    return map[string]any{"key": val}, nil
}
```

After:
```go
func (c *myComp) RunPhase3(
    ctx context.Context, globalConfig map[string]any, componentConfig any, prior map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
    return map[string]any{"key": val}, nil, nil
}
```

---

## New: declarative `Effect` system

Components return `FundingEffect`, `JobProposalEffect`, or `CLNodeConfigEffect`
values instead of calling shared infrastructure directly. The runtime executes
them after all components in a phase complete, in a fixed order.

```go
func (c *myComp) RunPhase3(...) (map[string]any, []devenvruntime.Effect, error) {
    return map[string]any{...}, []devenvruntime.Effect{
        devenvruntime.FundingEffect{
            ChainSelector: sel,
            Address:       addr,
            NativeAmount:  big.NewInt(5),
        },
        devenvruntime.JobProposalEffect{
            NOPAlias: nopAlias,
            NodeID:   jdNodeID,
            JobSpec:  tomlSpec,
        },
    }, nil
}
```
