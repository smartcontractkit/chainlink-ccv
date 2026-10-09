# noeagerio

`noeagerio` is a `go/analysis` linter that forbids I/O (RPC, DB, HTTP,
keystore/KMS) inside startup paths: exported `New*` constructors and `Start`
methods. See AGENTS.md ("Startup: no eager I/O in constructors or Start()")
for the policy and the outage history behind it.

Run it with:

```sh
just lint-noeagerio
```

## What it flags

- Direct calls to a denylist of I/O functions/methods (see `denyFuncs` and
  `denyMethods` in `analyzer.go`) anywhere in the synchronous body of a
  constructor or `Start` method.
- Calls to in-package helpers that (transitively) perform such I/O, reported
  at the call site in the startup function.

## What it deliberately allows

- I/O inside goroutines spawned from `Start` (`go func(){...}`,
  `wg.Go(func(){...})`, errgroup, ...) — the blessed pattern, provided the
  service reports progress via `Ready()`/`HealthReport()`.
- Closures registered for query-time execution (`common/lazy.New`).
- Anything outside constructors/`Start`.
- Call sites carrying `//nolint:noeagerio` with a justification (on the line,
  the line above, or the enclosing function's doc comment). A suppressed call
  does not taint its callers.

## Limitations

Taint propagation is intra-package only; the cross-package cases we know about
are covered by repo-specific denylist entries. A determined author can evade
the check (e.g. hiding I/O behind an unexported helper called from an
interface) — the analyzer is a tripwire, not a proof. Code review remains the
backstop.
