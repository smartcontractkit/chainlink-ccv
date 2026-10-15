# Human Overview

Runtime chain-liveness probes for the verifier and executor readers (CCIP-14099)
and standard probe paths on the bootstrap server (CCIP-14099/CCIP-14101 infra):

* `verifier/pkg/sourcereader`: the reader records the last successful chain query
  (every `readyToQuery` success, all loop modes) and `Ready()` now fails with
  `no successful chain query for <dur>` once the chain has not answered for
  50 poll intervals (~105s at the 2.1s default). Previously a mid-run RPC outage
  after a successful init left the reader reporting ready forever. A disabled
  chain is exempt (idle by design), and `finalityBlocked` keeps precedence.
  `ccip_chain_healthy` flips to 0 while queries fail and back to 1 on recovery;
  one stale chain degrades the verifier (HTTP 200), all stale chains make it
  not_ready (503).
* `integration/pkg/destinationreader`: the EVM execution-attempt poller applies
  the same staleness rule in HTTP polling mode (`no successful
  execution-attempt poll for <dur>` after 50 poll intervals, default 5s × 50).
  WebSocket mode is unchanged: push silence on a quiet chain is not anomalous,
  and subscription errors already reconnect or fall back to HTTP.
* `executor`: `ChainlinkExecutor.Ready()` now fails with `no destination reader
  is ready across N chain(s)` when every destination reader is down, and a new
  `Degraded()` names each unready `DestinationReader[<selector>]`. The
  coordinator's `Ready()` includes the executor's, and it delegates `Degraded()`,
  so `/health` reports `degraded` (200) when at least one destination chain is
  usable and `not_ready` (503) when none are — the same contract the verifier
  coordinator already follows.
* `bootstrap`: the info server on `[server].listen_port` (default 9988) now
  serves `/health/live` (shallow 200 `{"status":"alive"}`) and `/health/ready`
  (aliases the existing application-readiness handler, 200 `ready` / 503
  `not_ready`). JD-mode verifier/executor pods can now use the standard
  startupProbe/readinessProbe paths instead of the bespoke `/health` + `/ready`.
  The old paths are unchanged.

## Configuration

Both staleness thresholds default to 50 poll intervals and are overridable:

* Committee verifier TOML: `source_reader_staleness_threshold` (duration string,
  e.g. `"105s"`), validated like the other duration strings.
* Token verifier TOML: `source_reader_staleness_threshold` (duration).
* Executor TOML: `reader_staleness_threshold` (duration), validated non-negative
  and read by the chainaccess overlay that builds the destination readers.
* Programmatic: `vtypes.SourceConfig.StalenessThreshold` and
  `destinationreader.Params.ReaderStalenessThreshold` / the
  `NewEVMExecutionAttemptPoller` argument; zero selects the default.
