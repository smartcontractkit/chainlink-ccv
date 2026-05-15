# Add `Close()` to `chainaccess.Accessor` + `bootstrap.AccessorCloserRegistry`

## Executive Summary

- Adds `Close() error` to `chainaccess.Accessor` — idempotent, stateless impls return `nil`.
- Adds `bootstrap.AccessorCloserRegistry`, a registry wrapper that tracks every accessor and closes them all at shutdown.
- Both shutdown paths call `factory.Stop` first, then `CloseAll`. Both start paths defer `CloseAll` on partial failure.
- **Breaking change** for external `Accessor` implementers — accessor must add `Close()`.

## AI Adapter Index

| Symbol                                      | Kind  | Search                   | Location                                       | Section                                                    |
| ------------------------------------------- | ----- | ------------------------ | ---------------------------------------------- | ---------------------------------------------------------- |
| `chainaccess.Accessor.Close`                | added | `chainaccess\.Accessor`  | `pkg/chainaccess/interfaces.go:86`             | [#accessor-close-added](#accessor-close-added)             |
| `evm.accessor.Close`                        | added | `accessor\) Close\(`     | `integration/pkg/accessors/evm/factory.go:255` | [#accessor-close-added](#accessor-close-added)             |
| `bootstrap.AccessorCloserRegistry`          | added | `AccessorCloserRegistry` | `bootstrap/accessor_closer_registry.go:19`     | [#new-accessorcloserregistry](#new-accessorcloserregistry) |
| `bootstrap.AccessorCloserRegistry.CloseAll` | added | `\.CloseAll\(`           | `bootstrap/accessor_closer_registry.go:46`     | [#new-accessorcloserregistry](#new-accessorcloserregistry) |

## Breaking Changes

### Accessor Close added

- **What changed:** `chainaccess.Accessor` now requires `Close() error`.
- **Before:** No `Close` method.
- **After:** `Close() error` — releases background services. Idempotent: subsequent calls return `nil`.
- **Why:** Chain integrations that run background services (e.g. Solana log poller) need a shutdown hook.
- **Who is affected:** Any external implementer of `chainaccess.Accessor`. Solana accessor in `chainlink-ccip-solana` will fail to compile.

## Migration Guide

1. Add `Close() error` to your `Accessor` implementation.

```go
// Stateless (EVM)
func (a *accessor) Close() error { return nil }

// Stateful (Solana — use sync.Once for idempotency)
func (a *accessor) Close() error {
    a.closeOnce.Do(func() {
        if a.sourceLogPoller != nil {
            a.closeErr = a.sourceLogPoller.Close()
        }
    })
    return a.closeErr
}
```

2. Non-bootstrap callers (CLI, perf-bench) should `defer accessor.Close()`. Bootstrap-driven services get cleanup automatically via `AccessorCloserRegistry`.

## New: AccessorCloserRegistry

`bootstrap.AccessorCloserRegistry` wraps a `chainaccess.Registry`, tracks every `Accessor` returned by `GetAccessor`, and closes them all via `CloseAll`. Errors are joined; every accessor is attempted regardless of failures. Idempotent — a second `CloseAll` with no intervening `GetAccessor` returns `nil`.
