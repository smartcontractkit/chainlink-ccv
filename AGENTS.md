# AGENTS.md

Guidance for AI agents working in this repository. Read CONTRIBUTING.md for PR title and merge
mechanics. This file records conventions that are easy to get wrong by pattern-matching against
older code that predates them.

## Credentials: secrets file, not environment variables

New credentials are read from the service's secrets file only. Do not add an environment variable
for one.

The `VERIFIER_AGGREGATOR_*` env vars and `CL_DATABASE_URL` exist only for backwards compatibility
with deployments that predate the secrets file. A credential introduced after the file has no such
history, so it gets no env var and there is exactly one place an operator has to look. The
policy-hook HMAC pair is the model: `verifier/pkg/policy/auth.go` resolves it from the secrets
file's `[policy_hook]` table and nowhere else, and a half-supplied pair is a startup error rather
than a silent downgrade to no authentication.

Related: configuration that is marshaled into a Job Distributor job spec (for example the
verifier's `[policy_hook]` TOML section) must never carry a credential value, because the spec is
stored in JD. Reference where the secret lives; keep the value in the secrets file.

## Code comments: 3 lines max

Long comment blocks are hard to comprehend and takes a lot of space. State the
rule/behavior in one line, the reason in one more if it's non-obvious, and stop. If a comment
needs a paragraph, put that reasoning in the PR description or commit message instead.

## Startup: no eager I/O in constructors or Start()

Eager I/O at startup has caused multiple production outages (a rate-limited RPC
took down the whole committee verifier). Constructors (`New*`) only assemble
dependencies; `Start(ctx)` only spawns goroutines and returns. Any network, DB,
RPC, or keystore read must happen at query time — via `common/lazy.Lazy` for
cached-on-success derivations — or in a background goroutine that reports its
state through `Ready()`/`HealthReport()`. Per-chain and per-source failures
degrade: log, skip, record in the health report, and fail startup only when
*nothing* usable remains. A startup skip must also flip `Ready()` (register a
`common/health.StartupSkips` reporter, or the component's own report) so
`/health/ready` returns 503 — a skipped source should page, not vanish. The
`noeagerio` analyzer (`tools/noeagerio`, run by
`just lint-noeagerio` and CI) enforces this; a deliberate fail-fast exception
(identity keys, the service's own DB) needs `//nolint:noeagerio` with a reason.
