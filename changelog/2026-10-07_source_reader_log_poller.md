# EVM source reader reads CCIPMessageSent logs from the Chainlink node's LogPoller

## Executive Summary

- In CL mode, the EVM source reader reads `CCIPMessageSent` logs from the node's LogPoller instead of `eth_getLogs`. The standalone verifier still reads logs over RPC.
- With a LogPoller, the latest, safe, and finalized blocks the reader reports are capped at the LogPoller's last processed block, so the verifier never advances past logs that are not indexed yet.
- With a LogPoller, finality violations come from the LogPoller instead of the header-based checker, so the verifier makes no RPC calls for finality checks. A violation disables the source reader.
- In CL mode the source reader loads the LogPoller in the background: once the Service hands it the start block through `chainaccess.SourceLoader.LoadFrom`, it registers its `CCIPMessageSent` filter, deletes the LogPoller's logs and blocks from the start block when the filter already existed, and replays from the start block. Reads fail until that finishes, so construction no longer needs a live RPC and no range is checkpointed before it is indexed.
- On close, each source reader unregisters its own LogPoller filter, so deleting, cancelling, or updating a job removes its filter; a restart registers it again. Filter names change to `ccv-verifier - <verifierID>:<onramp>`.
- While a source reader is still loading, its reads fail with `chainaccess.ErrSourceNotReady`. The verifier logs this at info, not warn. The `source_reader_state` metric is unchanged and reports `poll_error` while loading.
- `DeleteLogsAndBlocksAfter` is chain-wide: other jobs on the chain briefly lose logs after the checkpoint until the replay refills them.
- No breaking changes for consumers. `evm.NewEVMSourceReader` takes a new trailing `*evm.LogPollerConfig` argument, but its only callers are in this repo and are updated. The Chainlink node calls `constructors.NewVerificationCoordinator`, whose signature does not change.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewEVMSourceReader` | signature-changed | `\bNewEVMSourceReader\(` | `integration/pkg/accessors/evm/evm_source_reader.go:101` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.SourceReader.FetchMessageSentEvents` | behavior-changed | `\.FetchMessageSentEvents\(` | `integration/pkg/accessors/evm/evm_source_reader.go:476` | [#log-source](#log-source) |
| `evm.SourceReader.LatestAndFinalizedBlock` | behavior-changed | `\.LatestAndFinalizedBlock\(` | `integration/pkg/accessors/evm/evm_source_reader.go:726` | [#block-capping](#block-capping) |
| `evm.SourceReader.LatestSafeBlock` | behavior-changed | `\.LatestSafeBlock\(` | `integration/pkg/accessors/evm/evm_source_reader.go:801` | [#block-capping](#block-capping) |
| `sourcereader.Service` finality checker | behavior-changed | `sourcereader\.NewService\(` | `verifier/pkg/sourcereader/finality_checker.go:348` | [#log-poller-finality](#log-poller-finality) |
| `sourcereader.Service` start | behavior-changed | `LoadFrom\(startBlock\)` | `verifier/pkg/sourcereader/service.go:236` | [#startup-load](#startup-load) |
| `sourcereader.Service` read errors | behavior-changed | `Source not ready yet, waiting` | `verifier/pkg/sourcereader/service.go:432` | [#startup-load](#startup-load) |
| `evm.LogPollerConfig` | behavior-changed | `\bLogPollerConfig\b` | `integration/pkg/accessors/evm/evm_source_reader.go:64` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.DefaultMessageSentLogRetention` | added | `\bDefaultMessageSentLogRetention\b` | `integration/pkg/accessors/evm/evm_source_reader.go:47` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.LogPollerEnabled` | added | `\bLogPollerEnabled\(` | `integration/pkg/accessors/evm/evm_source_reader.go:221` | [#log-poller-finality](#log-poller-finality) |
| `evm.NewLogPollerFinality` | added | `\bNewLogPollerFinality\(` | `integration/pkg/accessors/evm/evm_source_reader.go:231` | [#log-poller-finality](#log-poller-finality) |
| `evm.SourceReader.LoadFrom` | added | `\.LoadFrom\(` | `integration/pkg/accessors/evm/evm_source_reader.go:255` | [#startup-load](#startup-load) |
| `evm.SourceReader.Close` | added | `\.Close\(` | `integration/pkg/accessors/evm/evm_source_reader.go:363` | [#filter-lifecycle](#filter-lifecycle) |
| `evm.ErrLogPollerNotReady` | added | `\bErrLogPollerNotReady\b` | `integration/pkg/accessors/evm/evm_source_reader.go:54` | [#startup-load](#startup-load) |
| `evm.ErrLogPollerBehind` | added | `\bErrLogPollerBehind\b` | `integration/pkg/accessors/evm/evm_source_reader.go:51` | [#log-source](#log-source) |
| `chainaccess.FinalityViolationReporter` | added | `\bFinalityViolationReporter\b` | `pkg/chainaccess/interfaces.go:69` | [#log-poller-finality](#log-poller-finality) |
| `chainaccess.ErrSourceNotReady` | added | `\bErrSourceNotReady\b` | `pkg/chainaccess/interfaces.go:76` | [#startup-load](#startup-load) |
| `chainaccess.SourceLoader` | added | `\bSourceLoader\b` | `pkg/chainaccess/interfaces.go:80` | [#startup-load](#startup-load) |
| `verifier.WithFinalityReporters` | added | `\bWithFinalityReporters\(` | `verifier/pkg/coordinator.go:85` | [#log-poller-finality](#log-poller-finality) |
| `sourcereader.WithFinalityReporter` | added | `\bWithFinalityReporter\(` | `verifier/pkg/sourcereader/service.go:106` | [#log-poller-finality](#log-poller-finality) |

## Breaking Changes

*No breaking changes.* `evm.NewEVMSourceReader` has a new last parameter, but its only callers (`integration/pkg/accessors/evm/factory.go` and `integration/pkg/constructors/committee_verifier.go`) are in this repo and are updated. The Chainlink node builds the reader through `constructors.NewVerificationCoordinator`, which is unchanged.

## NewEVMSourceReader signature

The constructor has a new last parameter, `lpCfg *evm.LogPollerConfig`, after `onCriticalInvariant`. A direct caller passes `nil` to read logs over RPC, as before.

In CL mode, `constructors.newLogPollerConfig` (`integration/pkg/constructors/logpoller_filters.go:27`) builds it from the node's chain and database.

`evm.LogPollerConfig` (`integration/pkg/accessors/evm/evm_source_reader.go:65`):

| Field | Meaning |
|---|---|
| `LogPoller` | The node's `logpoller.LogPoller`. `nil` or `logpoller.LogPollerDisabled` falls back to RPC, so a node with the LogPoller disabled needs no special case. |
| `VerifierID` | Required when `lpCfg` is not nil; otherwise the constructor returns `log poller verifierID is not set`. Used in the filter name. |
| `Retention` | Filter log retention. `evm.DefaultMessageSentLogRetention` is 30 days; it must exceed the longest expected verifier outage. |
| `Ready` | The `logPollerReady` flag. Starts false; the startup routine sets it once the filter is registered and the LogPoller replayed. |
| `FilterRegistered` | Reports whether the node already stored the named filter (reads `evm.log_poller_filters`). |

With the LogPoller enabled, `Ready` and `FilterRegistered` are required; the constructor returns an error naming each missing one. The constructor makes no LogPoller or RPC call: it starts the startup routine described in [#startup-load](#startup-load).

## Log source

`FetchMessageSentEvents` reads from the LogPoller (`LogsWithSigs`) when one is configured, otherwise from `eth_getLogs`. The decoding and validation of logs are the same for both, in `parseMessageSentLogs`.

With a LogPoller:

- A `toBlock` of `0` means the LogPoller's last processed block (`LatestBlock`), not the chain head.
- Until the LogPoller is loaded, the call returns `evm.ErrLogPollerNotReady`.
- If `fromBlock` is above that block, the call returns `evm.ErrLogPollerBehind`, so the service retries instead of treating the range as scanned.
- The block timestamp is copied from the LogPoller log, because `ToGethLog` drops it.

## Block capping

With a LogPoller, if its last processed block `P` is below the head tracker's block:

| Method | Result |
|---|---|
| `LatestAndFinalizedBlock` | `latest` is the header at `P`. `finalized` is also the header at `P` when `P` is below the finalized block. |
| `LatestSafeBlock` | The header at `P` when `P` is below the safe block. `nil` stays `nil`. |

The header at `P` comes from `GetBlocksHeaders`. A missing header is an error. Without a LogPoller, both methods behave as before.

## Log poller finality

- `constructors.NewVerificationCoordinator` builds `evm.NewLogPollerFinality(chain.LogPoller())` per chain and passes the map with `verifier.WithFinalityReporters`. It is nil when `evm.LogPollerEnabled` is false, the same check that makes the reader read from the LogPoller, so the two cannot disagree.
- The coordinator hands each chain's reporter to its service with `sourcereader.WithFinalityReporter`. With one, the service uses `logPollerFinalityChecker` instead of the header-based checker. It reads only `FinalityViolated()`, which is true when the LogPoller's `Healthy()` returns `commontypes.ErrFinalityViolated`. It makes no RPC calls.
- The LogPoller clears its flag once it reconciles, so the checker latches the first violation. `handleFinalityViolation` disables the chain as before.
- `SourceConfig.DisableFinalityChecker` still wins and selects the no-op checker.
- A live recovery reset fails with `log poller still reports a finality violation` while the flag is set, and leaves the reader disabled.
- `chainaccess.FinalityViolationReporter` (`pkg/chainaccess/interfaces.go:69`) is the injected signal, not a reader capability, so reader decorators such as `integration/pkg/sourcereader/observed_source_reader.go` cannot hide or fake it.
- Accepted risk: the flag is sampled once per poll. A violation declared by the backup poller is re-declared on its next run, but one declared only by a LogPoller `Replay` can be cleared before it is read. The startup load retries a replay that hits a violation, so it is re-declared on each retry while it persists; it is missed only if the LogPoller reconciles before a poll samples it.

## Startup load

The LogPoller resumes after its own newest stored block, not the verifier's checkpoint. Without a replay it would not refill a range the verifier resumes in, such as after `chain-statuses set-finalized-height` or the first start with a new filter.

- `NewEVMSourceReader` starts a goroutine that waits for the start block. `Service.Start` hands it over through the optional `chainaccess.SourceLoader.LoadFrom` after `initializeStartBlock` (checkpoint + 1), on enabled and disabled chains alike. Only the first call counts.
- The routine checks whether the filter was already stored, registers it, deletes the LogPoller's logs and blocks from the start block with `DeleteLogsAndBlocksAfter` when it was, and calls `Replay` from the start block. A start block above the head tracker's latest block needs no replay.
- Failures are retried with backoff from 1s up to 1m until it succeeds or the reader closes. Whether the filter pre-existed is fixed on the first attempt.
- A replay that hits a finality violation sets the LogPoller's own violation flag, which `FinalityViolated` reports through `Healthy()` and which disables the chain. The load is retried.
- Until the load finishes, reads return `evm.ErrLogPollerNotReady`, which wraps `chainaccess.ErrSourceNotReady`. The service logs `Source not ready yet, waiting` at info instead of the `Error when querying logs` warning, and does not advance the checkpoint. `source_reader_state` still reports `poll_error`.
- `DeleteLogsAndBlocksAfter` is chain-wide: other LogPoller consumers on the chain lose logs after the start block until the replay refills them.
- Every restart replays from the checkpoint, normally about one finality depth of blocks. A deep `set-finalized-height` rewind replays the whole range.
- The standalone verifier and a disabled LogPoller read over RPC; `LoadFrom` is then a no-op.
- The metrics wrapper in `integration/pkg/sourcereader/observed_source_reader.go` forwards `LoadFrom` and `Close`. Other `SourceReader` wrappers must do the same.

## Filter lifecycle

Filters are named `ccv-verifier - <verifierID>:<onramp>`. `Service.Close` closes readers that implement `io.Closer`, and `evm.SourceReader.Close` stops the startup routine and unregisters the reader's own filter. A failed unregister is logged and does not fail `Close`.

| Path | Result |
|---|---|
| UI or CLI job delete, JD cancel | The job closes and its filter is unregistered. |
| JD update, onramp change | The old job unregisters its filter and the new one registers its own, then replays from the start block. |
| Node shutdown | Filters are unregistered; the next start registers them again and replays from the checkpoint, as every start does. Unmatched logs may be pruned in between, and the replay refills them from the checkpoint. |
| Node crash | The filter stays; the next start sees it already exists, deletes the LogPoller's data from the start block, and replays. |

Known limits: a job whose node crashed and which is then removed without the node running leaves its filter. Two jobs with the same `verifierID` and onramp would share a filter, so closing one removes the other's; a duplicate `verifierID` on a node is already a misconfiguration.

## Compatibility & Requirements

- **Dependency bumps:** none.
- **Supported environments:** only the CL-mode EVM verifier uses the LogPoller. The standalone verifier and non-EVM readers do not change.
- **Log retention:** logs older than the 30-day filter retention can be pruned before the verifier reads them. The startup load fetches them again from RPC, but they can be pruned again later.

## References

- Commits: `cba838c7` source reader log poller, `4c52b8ab`/`a112a7cf` finality violation from the LogPoller, `641f6887` startup replay, `c22ba7d7` background startup load, `d3b8dbfc`/`5332a027` filter lifecycle, `ace9425f`/`c3e6abd6` injected finality reporters. The CLI rewind is replaced by the startup load.
- Prior changelog entries this builds on: `2026-09-29_source_reader_block_confirmation.md`, `2026-09-11_source_recovery.md`.
