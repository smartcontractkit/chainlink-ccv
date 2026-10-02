# Admin console for verifier recovery (U1–U3)

## Executive Summary

- Adds `verifier ccv admin serve`: a server-rendered admin console (templ/htmx, Gin) shipped in both
  verifier images, wrapping the job-queue and recovery stores so operators can find, explain, and
  recover dropped messages without node shell access or CLI flags.
- Covers message search across an operator's nodes with unreachable-vs-empty separation, a per-message
  detail page (failure category, archive age/expiry, durable drop/incident evidence with coverage
  window, chain-status context), attestation freshness checks (anonymous aggregator reads + indexer
  lookup) gating reschedule, owner-scoped reschedule with preview and per-target outcomes, and a
  durable action log.
- Source-range recovery (replay/reset-reader) is driven through the durable R5 operations with
  progress, cancel/resume, and reload-safe tracking; R4 evidence is shown alongside the chosen range.
  Owned-indexer backfill reuses the indexer replay engine in-process and is hidden for operators
  without an indexer.
- Safety model: loopback bind by default (non-loopback requires an authenticating-proxy actor header),
  CSRF-protected mutations, credentials stay server-side in the existing secrets files, and every
  mutation is recorded in the console's own database — without it the console runs read-only.
- Console state is one Postgres table (`ccv_admin_actions`) migrated with a dedicated goose table, so
  it never collides with verifier migrations. No changes to verifier runtime behavior; the console is
  a separate process and never requires restarting a verifier.

## AI Adapter Index

Purely additive except for the CLI command table. Unlisted symbols keep their existing contracts.

| Symbol | Kind | Search | Location |
| --- | --- | --- | --- |
| `admin` package (console) | added | `verifier/pkg/admin` | `verifier/pkg/admin/` |
| `cli/admin.Command` | added | `admin\.Command` | `cli/admin/commands.go` |
| `ccv admin serve / check-config` | added | `ccv admin` | `cmd/verifier/run_ccv_cli.go` |

## Compatibility

The console administers standalone verifier databases. It connects to node databases the same way the
CLI does (verifier secrets file `[db].url`, migrations applied on connect) and only uses the live-safe
operations; the offline-only `ccv chain-statuses` mutations are deliberately not exposed.
