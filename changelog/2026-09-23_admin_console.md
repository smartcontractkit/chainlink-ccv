# Admin console for verifier recovery (U1–U3)

## Executive Summary

- Adds a server-rendered admin console (templ/htmx, Gin) shipped in both verifier images and
  served in-process by the verifier when a console config file is present, wrapping the
  job-queue and recovery stores so operators can find, explain, and recover dropped messages
  without node shell access or CLI flags.
- The console administers the verifier it runs beside — one console, one verifier. It shares
  that verifier's application database and secrets file, so there is nothing extra to
  provision: no console database, no per-node secrets references.
- Covers message search in the verifier's failed-job archive with lookup-failure-vs-empty
  separation, a per-message detail page (failure category, archive age/expiry, durable
  drop/incident evidence with coverage window, chain-status context), attestation freshness
  checks (the verifier's first configured aggregator's unauthenticated read API) gating
  reschedule, owner-scoped reschedule with preview and per-target outcomes, and a
  source-range recovery page (replay / reset-reader with durable operations).
- Every console mutation is audited in an in-memory, session-scoped action log (actor,
  target, outcome, detail) — matching the operator UI, which persists no such trail;
  persisting it is a follow-up if session history proves insufficient.
- Safety model: loopback bind by default (non-loopback requires `[admin_ui]` basic auth from
  the verifier secrets file), CSRF-protected mutations, and the config file is the only
  enable signal: `listen_address` and an optional `trace_url`.
- Packaging: a console config at `/etc/ccv-admin/config.toml` (`CCV_ADMIN_CONFIG_PATH`)
  enables the console; both verifier factories (committee and token, so alt-VM verifiers
  inherit it) serve it in-process on its own port and shut it down with the job. No config
  file means disabled.
- The `.templ` view sources regenerate through `go generate` (`templ` is pinned in
  tool-versions.env), so a stale committed `*_templ.go` fails the repo hygiene check.

## AI Adapter Index

Purely additive except for the CLI command table. Unlisted symbols keep their existing contracts.

| Symbol | Kind | Search | Location |
| --- | --- | --- | --- |
| `admin` package (console) | added | `verifier/pkg/admin` | `verifier/pkg/admin/` |
| `cli/admin.Command` (`ccv admin check-config`) | added | `admin\.Command` | `cli/admin/commands.go` |
| `startAdminConsole` (factory wiring) | added | `startAdminConsole` | `cmd/verifier/adminconsole.go` |
| `admin.BasicAuthFromSecrets / ValidateAccessPolicy` | added | `BasicAuthFromSecrets` | `verifier/pkg/admin/auth.go` |
| `vsecrets.VerifierSecrets.AdminUIAuth` | added | `AdminUIAuth` | `verifier/pkg/vsecrets/vsecrets.go` |
| `[admin_ui]` secrets table | added | `admin_ui` | `docs/config/verifier/secrets.documented.toml` |

## Compatibility

The console administers the standalone verifier's own application database. It only uses the
live-safe operations; the offline-only `ccv chain-statuses` mutations are deliberately not
exposed. The Chainlink-node integration is untouched: the console is wired in the standalone
factories only, and no new migrations are added (the audit log is in-memory).
