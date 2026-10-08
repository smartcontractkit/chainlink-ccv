# Admin console demo

A self-contained, disposable demo of the [CCV admin console](../admin-console.md)
for showing the team what it does. One command starts everything; nothing touches a real
environment, and `demo.sh stop` removes all of it.

- a disposable Postgres with a seeded verifier application database
- a seeded, realistic story: three failed messages, drop evidence, recovery history
- the console harness (`main.go`, built from this checkout): the **real**
  `verifier/pkg/admin` server, served in-process exactly as the verifier factory serves
  it, on `http://127.0.0.1:8105`
- a canned aggregator results client (injected via `admin.Deps.ResultsDialer`) so the
  reschedule attestation gate demos both verdicts without real infrastructure; the
  harness's "aggregator" is a stand-in for the verifier's first configured aggregator

The harness stands in for the verifier process: in production the verifier factory
serves the console when the config file is present; here the harness does it directly
over the seeded database.

## Quick start

![Demo walkthrough: search for a failed message, inspect its detail page, pass the
reschedule attestation preview, execute, and see it in the action log](demo.gif)

Prerequisites: Docker (running), Go, nc, curl.

```sh
docs/verifier/admin-console-demo/demo.sh          # or: .../demo.sh start
```

Open http://127.0.0.1:8105. When you are done:

```sh
docs/verifier/admin-console-demo/demo.sh stop     # stop console harness, remove container
docs/verifier/admin-console-demo/demo.sh clean    # also delete .runtime/ (build, logs)
```

Ports used: 8105 (console), 5433 (Postgres). Everything binds to loopback.
`demo.sh start` always begins from a clean slate, so re-running it resets the demo.

## The walkthrough

The seed data (see `seed-verifier.sql`) is one story: a remote-chain curse dropped a
message pre-admission; after the incident it was re-admitted and failed again in both
queues. Three message IDs carry it — easy to read out loud:

| Message ID (short form) | State | Point it makes |
| --- | --- | --- |
| `0xdeadbeef…deadbeef` | attested (the canned aggregator holds ccv data) | reschedule preview refuses: already attested |
| `0xcafebabe…cafebabe` | not attested; failed in both queues; drop evidence | the full journey: search → detail → reschedule |
| `0x0badf00d…0badf00d` | retry window expired | the detail page's age/expiry state |

1. **Safety model**, worth saying before clicking anything: loopback bind by default,
   every mutation CSRF-protected and written to the action log (in the same verifier
   database) with an intent row before it runs — an unloggable mutation never proceeds.

2. **Message search** (the home page redirects here): paste all three IDs (space or
   comma separated). Each row shows the failure category (`policy_rejected`,
   `validation_error`, `storage_failure`, `retry_window_expired`) — derived at read
   time from the archive, not hand-labeled.

3. **Message detail** for `0xcafebabe…`: failed rows from both queues (task-verifier
   and storage-writer), the durable drop evidence with its coverage window and the
   "empty results do not prove nothing happened" caveat, chain-status context, and the
   trace-viewer link from `demo-config.toml`.

4. **Reschedule** from the detail page:
   - `0xdeadbeef…` → preview says **already attested — nothing to do** and disables the
     target. The attestation check hit the harness's canned aggregator client and found
     ccv data.
   - `0xcafebabe…` → preview marks it executable (attestation: not found) and shows the
     saved payload it will reuse. Submit it: the job is restored to the active queue,
     and the action appears in the action log immediately.
   - Worth saying out loud: attestation `unknown` (aggregator unreachable or
     unconfigured) also disables the target — unknown is never proof that a replay is
     needed.

5. **Source recovery**: owner `CCTPVerifier`, chain `1`, range `1000`–`1200`. The preview
   shows the reader's head, the finalized-height warning (the range starts below the
   finalized height), and evidence from the incident. Submitting creates a durable
   operation; in production the running verifier's source reader performs it.
   - Then try chain `2`: replay is refused (the reader is finality-blocked) and the
     preview steers to **reset-reader**, the investigated action for that state. This is
     the replay/reset split the console enforces.

6. **Action log**: every mutation from the demo so far. The audit is deliberately
   in-memory and session-scoped (like the operator UI's, there is no persisted trail),
   so the page starts empty and shows only what you do live.

## What this demo deliberately does not show

- **Indexer backfill** is not offered: it is deferred with the indexer admin UI, exactly
  as for any operator whose indexer is another organization's. Indexer-data repair stays
  with the indexer's own replay tooling.
- **The real aggregator round-trip**: the harness injects a canned results client
  (`admin.Deps.ResultsDialer`); production wiring dials the aggregator's unauthenticated
  read API with the same message-level semantics (attested / not found / unknown).
- **Real finality/reorgs**: the seed data states are inserted, not produced by a chain.

## Troubleshooting

- **`port … is busy`** — something else owns 8105/5433; stop it or edit the port
  variables at the top of `demo.sh` (and `demo-config.toml` for the console port).
- **`go.mod requires go >= 1.26.6`** — the script pins `GOTOOLCHAIN=go1.26.6`
  (matching `tool-versions.env`); with `GOTOOLCHAIN=local` and an older Go this fails.
- **Console log** — `.runtime/console.log` (path is printed at startup).
- **`docker exec` errors** — the container is `ccv-admin-demo`; `docker rm -f
  ccv-admin-demo` then `demo.sh start` for a clean restart.
