# The CCV admin console

The admin console is a small web UI for finding and recovering dropped messages, shipped
inside the verifier image and served by the verifier binary:

```sh
verifier ccv admin serve --config /etc/ccv-admin/config.toml
```

Both verifier binaries (committee and token) carry it. It is a server-rendered UI
(templ/htmx) that talks directly to each configured verifier database and drives the same
recovery machinery as the `ccv job-queue` and `ccv recovery` CLIs, with the same
semantics. What it replaces is the manual part of those flows: pointing a CLI at one
database at a time, copying message IDs and owner IDs between commands, and keeping your
own notes about who did what. The console searches every configured node at once, shows
what happened to a message, executes the recovery action, and records it in an action
log. The [remediation runbook](../runbooks/remediating-stuck-or-dropped-messages.md)
reads console-first; the CLI remains the documented fallback.

What it does not change is the semantics: a reschedule from the console is the same
reschedule the CLI performs, against the same tables, with the same limits.

## Safety model

The console is a privileged tool: anyone who can load a page can, in principle, run a
recovery action against your verifier databases. The defaults assume it is a personal
operator tool, and anything beyond that is an explicit, validated choice.

- **Loopback by default.** `listen_address` defaults to `127.0.0.1:8105`. Reach it with
  an SSH port forward (`ssh -L 8105:127.0.0.1:8105 <host>`) and act as actor `local`.
- **Non-loopback requires an authenticating proxy.** Serving a page grants privileged
  actions, so the console refuses to start on a non-loopback address unless
  `access.actor_header` is set — the header your proxy writes after authenticating the
  caller. See [Shared hosting](#shared-hosting-and-the-access-model).
- **Credentials stay server-side.** The config references each node's verifier secrets
  file by path; database URLs are read from those files inside the process and are never
  rendered into a page or logged.
- **Mutations are CSRF-protected.** Every state-changing request must carry the
  per-browser token (form field `csrf_token` or header `X-CSRF-Token`) matching the
  `ccv_admin_csrf` cookie. Pages also ship restrictive security headers
  (`Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`).
- **Every mutation is recorded.** Actions are written to an action log in the console's
  own database with actor, node, target, outcome and detail. A mutation that cannot be
  logged does not proceed — an unaudited privileged action never runs silently.
- **No console database means read-only.** If the console secrets file is absent or has
  no `[db].url`, every page still renders but mutations are refused and no action
  history is kept. The home page shows a read-only banner in that state.

## Setup

The console takes one config file. The path comes from `--config`, then
`CCV_ADMIN_CONFIG_PATH`, then the default `/etc/ccv-admin/config.toml`. The file is
decoded strictly: unknown keys are a startup error, a missing file is an error, at least
one `[[nodes]]` entry is required, and node names must be unique.

### Minimal: one node, self-hosted

```toml
# /etc/ccv-admin/config.toml
listen_address = "127.0.0.1:8105"   # the default; shown for clarity

[console]
  secrets_path = "/etc/ccv-admin/secrets.toml"

[[nodes]]
  name = "committee-verifier-1"
  secrets_path = "/etc/committee-verifier/secrets.toml"
```

The console secrets file uses the verifier secrets schema
([reference](../config/verifier/secrets.documented.toml)); the console reads only its
`[db].url`, which points at a database the console owns for its action log:

```toml
# /etc/ccv-admin/secrets.toml
[db]
  url = "postgres://user:password@localhost:5432/ccv_admin?sslmode=disable"
```

`[console].secrets_path` may be omitted; the path then resolves from
`CCV_ADMIN_SECRETS_PATH`, then `/etc/ccv-admin/secrets.toml`. An absent file or an empty
`[db].url` is not an error — it selects read-only mode. A present but malformed file is
a startup error.

Each `[[nodes]]` entry is one verifier's application database. `secrets_path` points at
that verifier's own secrets file — the same file the verifier process loads — and the
console takes its `[db].url` from it. Keep the files mode-restricted and readable only
by the console process; never paste a URL into the console config itself.

### Several nodes: one operator's verifiers

```toml
[console]
  secrets_path = "/etc/ccv-admin/secrets.toml"

[[nodes]]
  name = "committee-verifier-1"
  secrets_path = "/etc/ccv-admin/node-secrets/committee-1.toml"
  aggregator_address = "aggregator-1:50051"
  indexer_url = "http://indexer:8100"
  trace_url = "https://traces.example.com"

[[nodes]]
  name = "token-verifier-1"
  secrets_path = "/etc/ccv-admin/node-secrets/token-1.toml"
```

Nodes must belong to you — the console is single-operator; there is no isolation between
configured nodes, and every action lands on whichever node you pick. Node databases
connect lazily on first use, so the console starts and stays up while a member is down;
an unreachable node is shown as unreachable, never as an empty result set. On first
connection the console applies pending verifier migrations to that database, exactly as
the CLI does.

### Optional per-node endpoints

| Field | What it enables |
| --- | --- |
| `aggregator_address` (host:port) | Attestation freshness checks via the aggregator's unauthenticated `GetVerifierResultsForMessage` — the message page can show whether a result already exists before you recover. |
| `indexer_url` (base URL) | The indexer's verification-result lookup for a message. |
| `indexer_config_path` | Points at an indexer's config file for an indexer **you own**, and enables the indexer-data backfill workflow. Leave it empty when you do not run the indexer; the console then hides that workflow. |
| `trace_url` (base URL) | Your trace viewer, linked from the message detail page. |

All four are per-node and independently optional; the home page lists each node's
capabilities so you can see what is enabled where.

### Validate before serving

```sh
verifier ccv admin check-config --config /etc/ccv-admin/config.toml
```

`check-config` runs the same loading and validation as `serve` and prints the listen
address and the resolved node identities (name and secrets path). Run it after every
config change — it catches misspelled keys, duplicate names, missing files and a
non-loopback bind without `access.actor_header` before the console does it at startup.

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

The console previews the exact nodes, owners and jobs a reschedule will touch and
rechecks attestation state before mutating — a message that already has a result is not
a reschedule candidate. Execution is one owner-scoped operation per target, reported per
target, and a retry re-runs only the targets that failed.

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
reloads and console restarts. Work is bounded — chunks of at most 100 blocks and 1,000
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

### Indexer-data backfill

For when the verifier and aggregator are fine and only the **indexer's view** of results
is wrong or incomplete. Available only on nodes with `indexer_config_path` set, i.e.
operators who own their indexer. Two modes: **discovery** by aggregator sequence number
to find what the indexer is missing, and **targeted repair** by message ID. Force and
overwrite are off by default — the backfill never silently rewrites rows the indexer
already holds.

What it does **not** do: re-admit anything on the verifier, re-run verification or
policy, or touch source-chain state. If a message was never verified, backfill cannot
help — use replay. Note that its inputs are aggregator sequence numbers and message IDs,
distinct from the source block numbers replay takes.

## Operations

**Upgrades.** The console ships in the verifier image, so it upgrades when your verifier
image does. It is a separate process from the verifier itself: starting, stopping or
upgrading the console does not require restarting the verifier, and recovery actions
submitted through it take effect on the running verifier (a restored job is picked up on
the queue's fallback poll). Run the console from the same image version as the verifiers
it administers — the console applies pending verifier migrations on first connect, as
the CLI does, and mixed-version expectations are the CLI's: recovery features need the
schema that carries them.

**Console state.** The console database is the console's only state: one table,
`ccv_admin_actions`, holding the action log. There is nothing else to back up or
migrate; the console runs its own migrations on startup. Losing the console database
loses the action history and returns the console to read-only mode — verifier state is
untouched, and re-pointing `[db].url` at a restored (or fresh) database is the whole
recovery procedure.

**Health.** `GET /healthz` returns `200 {"status":"ok"}`. It is a process liveness
check; per-node database reachability is on the home page, not in the health probe.

**Config checks.** `verifier ccv admin check-config` validates the config and prints the
resolved node identities without starting the server.

## Shared hosting and the access model

On loopback, every action is recorded as actor `local` — appropriate for a personal tool
reached over SSH. For a shared deployment, put the console behind an authenticating
proxy and set `access.actor_header` to the header the proxy writes after authentication
(for example `X-Authenticated-User`). That header's value becomes the actor in the
action log.

Two requirements fall on the proxy, because the console trusts the header verbatim:

1. The proxy must be the **only** network path to the console's listen address — anyone
   who can reach the port directly can set any actor.
2. The proxy must **strip or overwrite** the configured header on inbound requests
   before authenticating, so a client cannot supply its own identity. A request that
   arrives without the header is served as actor `unknown`; treat `unknown` entries in
   the action log as a proxy misconfiguration and fix it.

Config validation enforces the floor: a non-loopback `listen_address` with an empty
`access.actor_header` is a startup error. Everything above that floor is proxy hygiene.

**Verify the node list before acting.** The home page is the exact list of verifier
databases this console can mutate, with each node's reachability and capabilities. Node
names are the display and action-log identity — they are what the action log records, so
name nodes after the verifier they belong to, and re-check the list after any config
change or upgrade before running an action. An action against the wrong node is
recorded, but it is recorded against the wrong node.

## See also

- [Runbook: remediating a stuck or dropped message](../runbooks/remediating-stuck-or-dropped-messages.md) — the operational sequence, console-first.
- [Job-queue CLI reference](../../cli/jobqueue/README.md) — reschedule semantics, retention windows, owner resolution.
- [Live recovery CLI reference](../../cli/recovery/README.md) — replay and reset semantics, drop evidence, coverage limits.
- [Policy hook guide](../../verifier/docs/policy_hook.md) — the FAIL-then-clears flow a verification reschedule drives.
- [Config reference](../config/admin-console/config.documented.toml) — every config key, annotated.
