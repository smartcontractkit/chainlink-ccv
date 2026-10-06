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
* `aggregator/pkg`: `NewServer` returns errors instead of calling
  `logger.Fatalf` (signature changed to `(*Server, error)`); the caller in
  `main` owns the fail-fast decision.
* New `noeagerio` static analyzer (`tools/noeagerio`, run by
  `just lint-noeagerio` and the lint CI workflow) forbids I/O in constructors
  and `Start` methods repo-wide, with `//nolint:noeagerio` as the documented
  escape hatch for deliberate fail-fast exceptions. Policy recorded in
  AGENTS.md.

Deliberately unchanged (fail-fast by design, annotated with `//nolint:noeagerio`
+ justification): bootstrap DB connect/migrations and keystore/KMS key
verification, the JD lifecycle cached-job load, the commit signer keystore
read, the aggregator's own storage connect+migrate, the opt-in Redis rate
limiter, and the operator-run indexer replay tool.
