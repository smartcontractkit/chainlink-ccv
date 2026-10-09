# Human Overview

Reliability hardening against eager I/O at startup, the failure class behind
repeated verifier outages (see also PR #1424):

* `verifier/pkg/sourcereader`: `Start` no longer reads the DB/chain inline;
  start-block initialization retries in the background and `Ready()` reports
  until it succeeds. A transient RPC/DB failure can no longer abort startup.
* `verifier/pkg` coordinator: a per-chain source reader that fails to start is
  skipped, recorded in `HealthReport()`, and only fails the coordinator when
  no chain started at all. The all-chains chain-status read at coordinator
  start degrades to "unknown" instead of failing startup.
* `integration/pkg/cursechecker`: the initial RMN poll runs in the background
  goroutine instead of blocking `Start`.
* `cmd/verifier` token factory: one failing token verifier no longer prevents
  the others from starting (and `Fatalw` on unknown verifier type is now a
  returned error). Fails only when no verifier started.
* `indexer/cmd`: one failing verifier reader or discovery source no longer
  exits the process; fails only when none started.
* `pricer`: a chain that fails to start is skipped and surfaced via the new
  `HealthReport()`; fails only when no chain started.
* Startup skips are reported as degraded instead of vanishing. The indexer, token
  verifier, and committee verifier register a `common/health.StartupSkips`
  reporter, and the verifier coordinator and pricer report skips through
  `Degraded()`. A service with at least one usable chain stays in rotation:
  `/health` returns `status: degraded` with HTTP 200, and `services[].report`
  names each skipped component. A service with no usable chain fails startup, so
  a single-chain service whose chain is down exits and is restarted by its
  orchestrator. A verifier whose configured chains all fail to build a source
  reader service also fails startup now, instead of starting with no chains. The
  pricer also serves `/health` (alongside `/metrics`) for the first time.
* `aggregator/pkg`: `NewServer` returns errors instead of calling
  `logger.Fatalf` (signature changed to `(ctx, ...) (*Server, error)`); the
  caller in `main` owns the fail-fast decision.
* Startup DB work is now bounded by the caller's context:
  `common.EnsureDBConnectionContext` (the old `EnsureDBConnection` retried for
  ~40s ignoring the startup deadline) and `RunPostgresMigrationsContext` /
  `RunMigrationsContext` (goose `UpContext`; a hung migration no longer hangs
  startup forever). `cmd/verifier.ConnectToPostgresDB` takes a ctx.
* Accessor construction (RPC dial + chain service/TXM start) runs concurrently
  per chain with a 30s per-chain timeout in the committee verifier, token
  verifier, and executor factories, so one slow chain can no longer serialize
  away the shared startup budget; failures remain skip-and-log.
* `integration/pkg/messagerules`: the initial rules poll uses the
  service-lifetime context instead of the startup ctx that bootstrap cancels
  as soon as `Start` returns (the first fetch could previously be aborted).
* The coordinator's startup chain-status read is bounded (5s) in addition to
  being non-fatal.
* New `noeagerio` static analyzer (`tools/noeagerio`, run by `just lint` and
  the CI lint job via the lint recipe's lint-noeagerio dependency) forbids I/O
  in constructors and `Start` methods repo-wide, with `//nolint:noeagerio` as the documented
  escape hatch for deliberate fail-fast exceptions. Policy recorded in
  AGENTS.md.

Verified non-blocking by inspection: pyroscope `Start` (async uploader
goroutines) and beholder `SetupBeholder` (lazy gRPC client). Still structural
and accepted: JD-mode cached-job startup runs inside the lifecycle manager's
`Start` (its worst case shrinks with every fix above); a larger redesign would
move the startup deadline from the factory call to the readiness probe.

Deliberately unchanged (fail-fast by design, annotated with `//nolint:noeagerio`
+ justification): bootstrap DB connect/migrations and keystore/KMS key
verification, the JD lifecycle cached-job load, the commit signer keystore
read, the aggregator's own storage connect+migrate, the opt-in Redis rate
limiter, and the operator-run indexer replay tool.
