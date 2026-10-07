# The CCV admin console

The admin console is a small web UI for finding and recovering dropped messages, shipped
inside the verifier image and served **in-process** by the verifier itself. When the
container has a console config at `/etc/ccv-admin/config.toml` (override with
`CCV_ADMIN_CONFIG_PATH`), the verifier serves the console on its own port; no config
file means the console stays off. To enable it, add the config file (and optionally the
`[admin_ui]` credential) and restart the pod.

It is a server-rendered UI (templ/htmx) over the verifier's own application database —
the console administers the verifier it runs beside, and only that verifier. It drives
the same recovery machinery as the `ccv job-queue` and `ccv recovery` CLIs, with the
same semantics. What it replaces is the manual part of those flows: pointing a CLI at
the database, copying message IDs and owner IDs between commands, and keeping your own
notes about who did what. The console searches the failed-job archive, shows what
happened to a message, executes the recovery action, and records it in an action log.
The [remediation runbook](../runbooks/remediating-stuck-or-dropped-messages.md) reads
console-first; the CLI remains the documented fallback.

The console administers **verifier databases only** (committee and token verifiers).
Indexer-data backfill and other admin UIs are deliberately out of scope for now: repair
indexer records with the indexer's own replay tooling until that workflow ships.

What it does not change is the semantics: a reschedule from the console is the same
reschedule the CLI performs, against the same tables, with the same limits.

## Safety model

The console is a privileged tool: anyone who can load a page can, in principle, run a
recovery action against your verifier. The defaults assume it is a personal operator
tool, and anything beyond that is an explicit, validated choice.

- **Loopback by default.** `listen_address` defaults to `127.0.0.1:8105`. Reach it with
  an SSH port forward (`ssh -L 8105:127.0.0.1:8105 <host>`) and act as actor `local`.
- **Non-loopback requires an identity source.** Serving a page grants privileged
  actions, so the console refuses to start on a non-loopback address unless either
  `access.actor_header` is set (an authenticating proxy writes the header) or
  `[admin_ui]` basic auth is configured in the verifier secrets file (the console
  verifies the credential itself). See [Shared hosting](#shared-hosting-and-the-access-model).
- **Optional basic auth.** `[admin_ui]` username + password in the verifier secrets file
  gates every page except `/healthz` (kept open for probes); the authenticated username
  becomes the action-log actor. A half-supplied pair is a startup error, never a silent
  downgrade to unauthenticated serving.
- **No new credentials or databases.** The console shares the verifier's application
  database and its secrets file; there is nothing extra to provision. Database URLs are
  never rendered into a page or logged.
- **Mutations are CSRF-protected.** Every state-changing request must carry the
  per-browser token (form field `csrf_token` or header `X-CSRF-Token`) matching the
  `ccv_admin_csrf` cookie. Pages also ship restrictive security headers
  (`Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`).
- **Every mutation is recorded.** Actions are written to the `ccv_admin_actions` table
  in the verifier's application database with actor, target, outcome and detail. Each
  mutation writes an intent row (`outcome=started`) before touching anything, then an
  outcome row after it; a mutation that cannot be logged does not proceed — an
  unaudited privileged action never runs silently.

## Setup

Add `/etc/ccv-admin/config.toml` (path override: `CCV_ADMIN_CONFIG_PATH`) and restart
the verifier. The file is decoded strictly: unknown keys are a startup error, and a
present-but-malformed file fails startup. The minimal config is empty — every field is
optional:

```toml
# /etc/ccv-admin/config.toml
listen_address = "127.0.0.1:8105"   # the default; shown for clarity
```

Optional fields:

| Field | What it enables |
| --- | --- |
| `aggregator_address` (host:port) | Overrides the aggregator used for attestation freshness checks (`GetVerifierResultsForMessage`). Default: the verifier's own first configured aggregator; a token verifier has none, so set it here if you want freshness checks. |
| `trace_url` (base URL) | Your trace viewer (e.g. an internal Grafana/Tempo or Jaeger), linked from the message detail page. |
| `access.actor_header` | The authenticated-identity header written by your fronting proxy; see [Shared hosting](#shared-hosting-and-the-access-model). |

Basic auth, if you want it, goes in the verifier secrets file — the same file the
verifier process loads
([reference](../config/verifier/secrets.documented.toml)):

```toml
# <verifier secrets file>
[admin_ui]
  username = "operator"
  password = "<password>"
```

### Validate before restarting

```sh
verifier ccv admin check-config --config /etc/ccv-admin/config.toml
```

`check-config` runs the same loading and validation as startup and prints the listen
address and access mode. Run it after every config change — it catches misspelled keys
and malformed files before the verifier does it at startup.

## The recovery actions

Each action below is the console form of the corresponding CLI flow and inherits its
semantics and limits. Links go to the CLI references, which remain authoritative.

### Verification reschedule

For a message whose verification job failed and sits in the archive — the classic case
being a policy endpoint that answered FAIL and has since been cleared. The console
restores the archived job to the active queue; the running verifier picks it up on its
next queue poll (normally within about 30 seconds) and **runs verification and the
policy call again** on the saved payload. This is the supported FAIL-then-clears path
from the [policy hook guide](../../verifier/docs/policy_hook.md): clearing your endpoint
does not bring a message back on its own; rescheduling asks the endpoint again, and the
second call can answer PASS.

The console previews the exact owners and jobs a reschedule will touch and rechecks
attestation state before mutating — a message that already has a result is not a
reschedule candidate. Execution is one owner-scoped operation per target, reported per
target. The archive-row and attestation gate re-runs on **every** execution — a direct
execute post, a retry, or a preview that has gone stale — and each mutation writes its
action-log intent row before it runs; a retry resubmits only the targets that failed or
were skipped.

What it does **not** do: re-read the source event, or repeat source-reader finality,
curse or disablement admission checks. It cannot tell you whether the event is still
canonical after a reorg — that is source replay's job. It never bypasses policy: the
endpoint is asked again and can FAIL again. And it works only while the archive row is
retained: automatic retry runs for 7 days, failed rows are archived immediately, and
archives are deleted 30 days after archiving (swept every 4 hours). An expired archive
row can no longer be rescheduled; use source replay.

### Storage reschedule

Verification completed and a result was saved, but delivering it to storage failed. The
reschedule restores the `storage-writer` job and **only persistence runs again** — the
saved result is delivered as-is. The same limits apply: no source re-read, no admission
re-checks, and no effect once the archive row has expired.

### Source-range replay

For messages that never entered the queue: dropped before admission by a curse or a
disablement rule, missed while the reader was down, or aged out of the archive. The
console submits a durable recovery operation for an **inclusive source block range**;
the live source reader re-reads that range from the chain and re-runs full admission —
event filter, message-ID validation, curse check, disablement rules, finality — then
publishes ordinary verification tasks, so normal verification and policy processing
apply to whatever it finds. No policy or chain-specific bypass exists on this path.

Submission requires block bounds and an **evidence note** (the incident reference and
why the range is being replayed); the actor is taken from your session. Bounds are fixed
at submission and never follow the moving head. The operation is durable: you can watch
progress, counters and `last_error` on the recovery page, and cancel/resume across
reloads and restarts. Work is bounded — chunks of at most 100 blocks and 1,000
events, one chunk per owner at a time, normal traffic continues, and the normal reader
checkpoint is never rewound by an ordinary replay.

What it does **not** do: admit an event that fails current admission checks (a still-
cursed source stays dropped — clear the root cause first), reconcile old failed archive
rows against new attestations, or release a finality-disabled reader. `completed` means
the range's queue work committed; confirm the affected messages' final attestations
separately, exactly as in the CLI flow.

### Investigated reader reset

The special case of replay for a reader **disabled by a finality violation or disabled
at startup**. Ordinary replay never clears a disablement; the reset is an explicit,
recorded operator decision about canonical history. You establish the known-good
boundary out of band (compare stored/observed hashes against canonical RPC headers — the
first detected mismatch may be later than the earliest affected block), then submit the
reset with your evidence note. The console seeds a fresh finality checker at
`from-block - 1` and the reset **owns normal polling until its range completes**;
cancelling or failing it keeps that pause deliberately, and resuming the same operation
finishes it. A later finality violation stays sticky and needs a **new** investigated
reset — resuming an old applied reset cannot clear it. Published jobs and previous
attestations are never deleted by a reset; there is no automatic undo of prior results.

## Operations

**Upgrades.** The console ships in the verifier image and runs in the verifier process,
so it upgrades when your verifier image does — there is nothing separate to deploy.
Recovery actions submitted through it take effect on the running verifier (a restored
job is picked up on the queue's fallback poll). Run the console from the same image
version as the verifier it administers: recovery features need the schema that carries
them, and the console's action table is created by the verifier's own migrations.

**Console state.** The action log (`ccv_admin_actions`) lives in the verifier's
application database and is created by the verifier's migrations; there is no separate
console database to provision, back up, or migrate.

**Health.** `GET /healthz` returns `200 {"status":"ok"}`. It is a process liveness
check only.

**Config checks.** `verifier ccv admin check-config` validates the config file without
starting anything.

## Shared hosting and the access model

On loopback, every action is recorded as actor `local` — appropriate for a personal tool
reached over SSH. A shared deployment needs an identity source; the console refuses to
start on a non-loopback address (including a wildcard bind) unless at least one is
configured:

- **`access.actor_header` (authenticating proxy).** The console trusts the configured
  header verbatim; its value becomes the actor in the action log.
- **`[admin_ui]` basic auth (verifier secrets file).** The console verifies the
  credential itself on every request except `/healthz` (kept open for probes), and the
  username becomes the actor. No proxy is required for identity — but basic auth carries
  the password base64-encoded, so serve it over TLS (or keep the console on loopback and
  SSH-forward). When both are configured, the basic-auth username wins: the header is
  client-supplied, the basic-auth credential is not.

When the proxy is the identity source, two requirements fall on the proxy, because the
console trusts the header verbatim:

1. The proxy must be the **only** network path to the console's listen address — anyone
   who can reach the port directly can set any actor.
2. The proxy must **strip or overwrite** the configured header on inbound requests
   before authenticating, so a client cannot supply its own identity. A request that
   arrives without the header is served as actor `unknown`; treat `unknown` entries in
   the action log as a proxy misconfiguration and fix it.

Startup validation enforces the floor: a non-loopback `listen_address` with neither
`access.actor_header` nor `[admin_ui]` fails to start. Everything above that floor is
proxy hygiene (or basic auth over TLS).

## See also

- [Runbook: remediating a stuck or dropped message](../runbooks/remediating-stuck-or-dropped-messages.md) — the operational sequence, console-first.
- [Job-queue CLI reference](../../cli/jobqueue/README.md) — reschedule semantics, retention windows, owner resolution.
- [Live recovery CLI reference](../../cli/recovery/README.md) — replay and reset semantics, drop evidence, coverage limits.
- [Policy hook guide](../../verifier/docs/policy_hook.md) — the FAIL-then-clears flow a verification reschedule drives.
- [Config reference](../config/admin-console/config.documented.toml) — every config key, annotated.
