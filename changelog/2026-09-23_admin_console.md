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
  checks (anonymous aggregator reads) gating reschedule, owner-scoped reschedule with preview
  and per-target outcomes, and a durable action log.
- Source-range recovery (replay/reset-reader) is driven through the durable R5 operations with
  progress, cancel/resume, and reload-safe tracking; R4 evidence is shown alongside the chosen
  range. Indexer-data backfill is out of scope for now (deferred with the indexer admin UI);
  indexer repair stays with the indexer's own replay tooling.
- Safety model: loopback bind by default (non-loopback requires an identity source — an
  authenticating-proxy actor header or `[admin_ui]` basic auth from the verifier secrets
  file), CSRF-protected mutations, and every mutation recorded with an intent row before it
  runs — an unaudited mutation never proceeds.
- Console state is one Postgres table (`ccv_admin_actions`) created by the verifier's own
  migrations, alongside the stores it administers. No changes to verifier runtime behavior
  when the config file is absent.
- Packaging: a console config at `/etc/ccv-admin/config.toml` (`CCV_ADMIN_CONFIG_PATH`)
  enables the console; both verifier factories (committee and token, so alt-VMs inherit it)
  serve it in-process on its own port and shut it down with the job. No config file means
  disabled.

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
| `ccv_admin_actions` table | added | `00010_admin_actions` | `verifier/migrations/postgres/00010_admin_actions.sql` |

## Compatibility

The console administers the standalone verifier's own application database. It only uses the
live-safe operations; the offline-only `ccv chain-statuses` mutations are deliberately not
exposed. The Chainlink-node integration is untouched: the console is wired in the standalone
factories only.
