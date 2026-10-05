# Composable verifier gates

## Executive Summary

- `vtypes.Decorator` and `vtypes.Chain` give the verifier construction sites one shape for
  wrapping a verifier. Adding a second gate is appending an entry to a `Chain` call rather than
  writing another bespoke wrapper around `Verifier`.
- `policy.WrapVerifier` is replaced by `policy.Gate`, a decorator factory. Same behavior, same
  enable condition, same nil-config pass-through; what changed is that the gate no longer takes
  the verifier it wraps as a parameter. See Breaking Changes.
- No runtime change. A verifier with no `[policy_hook]` section has the same call path as before,
  and a verifier with one gets the same `GatedVerifier` around the same commit verifier.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `vtypes.Decorator` / `vtypes.Chain` | added | `func Chain\(` | `verifier/pkg/vtypes/decorator.go:23` | [#the-decorator](#the-decorator) |
| `policy.Gate` | added | `func Gate\(` | `verifier/pkg/policy/gate.go:327` | [#the-decorator](#the-decorator) |
| `policy.WrapVerifier` | removed | `WrapVerifier` | `verifier/pkg/policy/gate.go` (deleted) | [#breaking-changes](#breaking-changes) |
| `verifier.Decorator` | added | `Decorator\s+= vtypes\.Decorator` | `verifier/pkg/interfaces.go:14` | [#the-decorator](#the-decorator) |

## Breaking Changes

`policy.WrapVerifier` is gone. `policy.Gate` returns a `vtypes.Decorator` that takes the inner
verifier instead:

```go
// before
gated, err := policy.WrapVerifier(lggr, verifierID, commitVerifier, cfg.PolicyHook, monitoring, cred)

// after
gated, err := vtypes.Chain(commitVerifier, policy.Gate(lggr, verifierID, cfg.PolicyHook, monitoring, cred))
```

No deprecated `WrapVerifier` shim is kept. Its only two call sites were in this repo: the
standalone factory, updated here, and the Chainlink-node constructor, which stopped calling it in
`2026-09-05_policy_hook_standalone_only.md` when the hook became standalone-only. A forwarding
shim would be dead code from the day it landed, and the rename is the point of the change rather
than a side effect of it.

## The decorator

`vtypes.Decorator` is `func(inner Verifier) (Verifier, error)`. A factory captures its own
configuration and returns one, so the construction site sees a single shape regardless of what the
gate needs to be built. A decorator with nothing to add returns its argument unchanged, which is
how a nil `[policy_hook]` leaves no extra layer in the call path.

`vtypes.Chain(inner, decorators...)` applies them outermost-first: the first listed decorator sees
every task before the rest of the chain. It is applied in reverse internally so that reading the
call site top to bottom matches the order tasks flow through. A nil decorator is skipped, so a
factory may return nil for "not configured" instead of a pass-through. A decorator that returns a
nil verifier without an error is an error, not a silent hole in the chain.

`policy.Gate` is the first decorator. Its body is `WrapVerifier`'s, unchanged: the `require_auth`
credential check, the HTTP checker, the retry delay, the `GatedVerifier`, and the "Policy hook
enabled" boot line all behave as before.
