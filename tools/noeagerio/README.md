# noeagerio

`noeagerio` is a `go/analysis` linter that forbids I/O (RPC, DB, HTTP,
keystore/KMS) inside startup paths: exported `New*` constructors and `Start`
methods. See AGENTS.md ("Startup: no eager I/O in constructors or Start()")
for the policy and the outage history behind it.

Run it with:

```sh
just lint   # noeagerio runs as a lint dependency; or standalone: just lint-noeagerio
```

## What it flags

- Direct calls to a denylist of I/O functions/methods (see `denyFuncs` and
  `denyMethods` in `analyzer.go`, including repo entrypoints like
  `common.EnsureDBConnectionContext`, the migration helpers, and
  `Registry.GetAccessor`) anywhere in the synchronous body of a constructor or
  `Start` method.
- Calls to in-package helpers that (transitively) perform such I/O, reported
  at the call site in the startup function.
- Cross-package denylisted functions by qualified name.

## What it deliberately allows

- Closures **created but not executed**: a closure body passed to an unknown
  API, stored in a field, or returned is not walked — creating a callback
  performs no I/O. Exceptions: immediately-invoked closures, and closures
  passed to known synchronous callback invokers (`services` `StartOnce`/
  `StopOnce`), which run inline and are walked.
- Goroutine launches through **known APIs only**: `sync.WaitGroup.Go` and
  `errgroup.Group.Go` (resolved by receiver, not spelling). A lookalike method
  named `Go` on another type gets no exemption. Argument expressions of a
  launch (`go consume(load())` → `load()`) are still walked: they evaluate
  eagerly.
- Closures registered for query-time execution via
  `github.com/smartcontractkit/chainlink-ccv/common/lazy.New` (matched by
  import path, and generic instantiations like `lazy.New[string](...)` are
  unwrapped).
- Anything outside constructors/`Start`, `_test.go` files, and unexported
  non-`Start` functions.

## Escape hatch

`//nolint:noeagerio // <written reason>` on the finding's line, the line
above, or the enclosing function's doc comment. The justification text is
required: a bare directive does not suppress anything. A suppressed call does
not taint its callers, so one justification covers the whole call chain.

## Limitations

- Taint propagation is intra-package; known cross-package cases are covered
  by qualified denylist entries instead.
- A closure stored in a field and invoked from `Start` (e.g. `vc.initFn(ctx)`)
  is invisible: creation and invocation are in different functions and the
  invocation goes through a field, not a local edge.
- A synchronous callback passed to an *unknown* invoker is skipped
  (created-not-executed). Known synchronous invokers are enumerated in
  `syncCallbackInvokers`.
- The analyzer is a tripwire, not a proof. Code review remains the backstop.
