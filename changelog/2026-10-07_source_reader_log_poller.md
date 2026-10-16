# CL-mode verifier reads CCIPMessageSent logs from the Chainlink node's LogPoller

## Executive Summary

- In CL mode, each EVM chain with the node's LogPoller enabled gets a new `evm.LogPollerSourceReader`. It reads `CCIPMessageSent` logs from the LogPoller instead of `eth_getLogs`. Chains with the LogPoller disabled, and the standalone verifier, keep the RPC `evm.SourceReader`.
- The LogPoller reader takes latest, safe, and finalized blocks from the LogPoller's last processed block, not the head tracker, so the verifier never checkpoints a range the LogPoller has not indexed.
- On those chains, the LogPoller's own finality-violation signal replaces the header-based finality checker, so finality checks make no RPC calls. The signal is passed to the verifier with `verifier.WithFinalityReporters`.
- The reader loads the LogPoller in the background after the source reader service gives it the start block (`chainaccess.SourceLoader.LoadFrom`). On every start, loading registers the filter, deletes the LogPoller's logs and blocks from the start block, anchors an emptied LogPoller at the checkpoint, and replays. Reads fail with `chainaccess.ErrSourceNotReady` until the load finishes, and the chain reports not ready and unhealthy until then.
- On close, the reader unregisters its own filter, named `ccv-verifier - <verifierID>:<onramp>`.
- `evm.NewEVMSourceReader` now takes an `evm.SourceReaderParams` struct. Its only callers are in this repo and are updated. The Chainlink node calls `constructors.NewVerificationCoordinator`, whose signature does not change, so consumers have no breaking changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewEVMSourceReader` | signature-changed | `\bNewEVMSourceReader\(` | `integration/pkg/accessors/evm/evm_source_reader.go:76` | [#source-reader-constructors](#source-reader-constructors) |
| `sourcereader.NewService` | signature-changed | `sourcereader\.NewService\(` | `verifier/pkg/sourcereader/service.go:114` | [#log-poller-finality](#log-poller-finality) |
| `sourcereader.Service` start and close | behavior-changed | `\bSourceLoader\b` | `verifier/pkg/sourcereader/service.go:238` | [#startup-load](#startup-load) |
| `sourcereader.Service.Ready` and chain health | behavior-changed | `RecordChainHealthy\(` | `verifier/pkg/sourcereader/service.go:286` | [#load-health](#load-health) |
| `sourcereader.Service` read errors | behavior-changed | `Source not ready yet, waiting` | `verifier/pkg/sourcereader/service.go:443` | [#startup-load](#startup-load) |
| `sourcereader.Service` recovery reset | behavior-changed | `still reports a finality violation` | `verifier/pkg/sourcereader/recovery.go:189` | [#log-poller-finality](#log-poller-finality) |
| `constructors.NewVerificationCoordinator` | behavior-changed | `constructors\.NewVerificationCoordinator\(` | `integration/pkg/constructors/committee_verifier.go:43` | [#reader-selection](#reader-selection) |
| `evm.SourceReaderParams` | added | `\bSourceReaderParams\b` | `integration/pkg/accessors/evm/evm_source_reader.go:39` | [#source-reader-constructors](#source-reader-constructors) |
| `evm.NewLogPollerSourceReader` | added | `\bNewLogPollerSourceReader\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:96` | [#source-reader-constructors](#source-reader-constructors) |
| `evm.LogPollerConfig` | added | `\bLogPollerConfig\b` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:48` | [#source-reader-constructors](#source-reader-constructors) |
| `evm.DefaultMessageSentLogRetention` | added | `\bDefaultMessageSentLogRetention\b` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:32` | [#source-reader-constructors](#source-reader-constructors) |
| `evm.LogPollerEnabled` | added | `\bLogPollerEnabled\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:56` | [#reader-selection](#reader-selection) |
| `evm.NewLogPollerFinality` | added | `\bNewLogPollerFinality\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:66` | [#log-poller-finality](#log-poller-finality) |
| `evm.LogPollerSourceReader.FetchMessageSentEvents` | added | `\.FetchMessageSentEvents\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:265` | [#log-reads](#log-reads) |
| `evm.LogPollerSourceReader.LatestAndFinalizedBlock` | added | `\.LatestAndFinalizedBlock\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:335` | [#block-heads](#block-heads) |
| `evm.LogPollerSourceReader.LatestSafeBlock` | added | `\.LatestSafeBlock\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:348` | [#block-heads](#block-heads) |
| `evm.LogPollerSourceReader.LoadFrom` | added | `\.LoadFrom\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:127` | [#startup-load](#startup-load) |
| `evm.LogPollerSourceReader.Loaded` | added | `\.Loaded\(\)` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:139` | [#load-health](#load-health) |
| `evm.LogPollerSourceReader.Close` | added | `\.Close\(` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:244` | [#filter-lifecycle](#filter-lifecycle) |
| `evm.ErrLogPollerNotReady` | added | `\bErrLogPollerNotReady\b` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:39` | [#startup-load](#startup-load) |
| `evm.ErrLogPollerBehind` | added | `\bErrLogPollerBehind\b` | `integration/pkg/accessors/evm/evm_logpoller_source_reader.go:36` | [#log-reads](#log-reads) |
| `chainaccess.FinalityViolationReporter` | added | `\bFinalityViolationReporter\b` | `pkg/chainaccess/interfaces.go:69` | [#log-poller-finality](#log-poller-finality) |
| `chainaccess.ErrSourceNotReady` | added | `\bErrSourceNotReady\b` | `pkg/chainaccess/interfaces.go:76` | [#startup-load](#startup-load) |
| `chainaccess.SourceLoader` | added | `\bSourceLoader\b` | `pkg/chainaccess/interfaces.go:80` | [#startup-load](#startup-load) |
| `verifier.WithFinalityReporters` | added | `\bWithFinalityReporters\(` | `verifier/pkg/coordinator.go:86` | [#log-poller-finality](#log-poller-finality) |
| `sourcereader.WithFinalityReporter` | added | `\bWithFinalityReporter\(` | `verifier/pkg/sourcereader/service.go:108` | [#log-poller-finality](#log-poller-finality) |

## Breaking Changes

*No breaking changes for consumers.* `evm.NewEVMSourceReader` takes a params struct now. Its only callers, `integration/pkg/accessors/evm/factory.go` and `integration/pkg/constructors/committee_verifier.go`, are in this repo and are updated. `sourcereader.NewService` gets a trailing variadic `...ServiceOption`, so existing calls still compile.

## Source reader constructors

The RPC reader and the LogPoller reader share an unexported `sourceReaderCore`, which handles block headers, head tracker reads, RMN curse reads, and `CCIPMessageSent` decoding. Their constructors take the same `evm.SourceReaderParams`.

```go
// Before
evm.NewEVMSourceReader(ctx, chainClient, headTracker, onRamp, rmnRemote, topic, sel, lggr, batchSize, onCriticalInvariant)

// After
p := evm.SourceReaderParams{
	ChainClient:                chainClient,
	HeadTracker:                headTracker,
	OnRampAddress:              onRamp,
	ConfiguredRMNRemoteAddress: rmnRemote, // deprecated, zero when unset
	CCIPMessageSentTopic:       topic,
	ChainSelector:              sel,
	Logger:                     lggr,
	HeaderFetchBatchSize:       batchSize,
	OnCriticalInvariant:        onCriticalInvariant, // optional
}
evm.NewEVMSourceReader(ctx, p)                // RPC logs
evm.NewLogPollerSourceReader(ctx, p, lpCfg)   // LogPoller logs
```

`evm.LogPollerConfig`:

| Field | Meaning |
|---|---|
| `LogPoller` | The node's `logpoller.LogPoller`. Must satisfy `evm.LogPollerEnabled`. |
| `VerifierID` | Required. Used in the filter name. |
| `Retention` | Filter log retention. `evm.DefaultMessageSentLogRetention` is 30 days; it must exceed the longest expected verifier outage. |

In CL mode, `constructors.newLogPollerConfig(chain, verifierID)` builds it. `NewLogPollerSourceReader` returns one error listing every missing or invalid field. It makes no LogPoller or RPC calls.

## Reader selection

For each chain, `constructors.NewVerificationCoordinator` checks `evm.LogPollerEnabled(chain.LogPoller())`. The LogPoller counts as enabled when it is neither nil nor `logpoller.LogPollerDisabled`.

| LogPoller | Reader | Finality checker |
|---|---|---|
| Enabled | `NewLogPollerSourceReader` | LogPoller signal (`evm.NewLogPollerFinality`) |
| Disabled | `NewEVMSourceReader` | Header-based |

The same check picks both the reader and the finality checker, so the two always match. The standalone accessor factory always builds the RPC reader.

## Log reads

`LogPollerSourceReader.FetchMessageSentEvents`:

- Returns `evm.ErrLogPollerNotReady` until the startup load finishes.
- Rejects `fromBlock > toBlock` when `toBlock` is not 0.
- A `toBlock` of `0` means the LogPoller's last processed block (`LatestBlock`), not the chain head.
- If either end of the range is above the LogPoller's last processed block, it returns `evm.ErrLogPollerBehind`, so the service retries instead of treating the range as scanned.
- Reads with `LogsWithSigs`. It copies the block timestamp from the LogPoller log, because `ToGethLog` drops it.

## Block heads

The LogPoller reader does not read the head tracker for these methods. Both start from the LogPoller's `LatestBlock`, which stores the finalized and safe block numbers the LogPoller read from the head tracker when it polled.

| Method | Result |
|---|---|
| `LatestAndFinalizedBlock` | `latest` is the LogPoller's last processed block. `finalized` is the block at the `FinalizedBlockNumber` saved with it. |
| `LatestSafeBlock` | The block at the `SafeBlockNumber` saved with the last processed block. It is never `nil`. |

- The finalized and safe headers come from the LogPoller's `GetBlocksRange`, which reads its own stored blocks and falls back to RPC only for a block it has not stored. A missing block is an error.
- These headers have a zero `ParentHash`, because the LogPoller does not store parent hashes. Only the header-based finality checker reads `ParentHash`, and LogPoller chains do not use it.
- The RPC `SourceReader` still reads the head tracker, as before.

## Log poller finality

- `NewVerificationCoordinator` passes each chain's `evm.NewLogPollerFinality(lp)` in a map to `verifier.WithFinalityReporters`. The coordinator hands each entry to its service with `sourcereader.WithFinalityReporter`. A nil reporter keeps the header-based checker.
- `newFinalityChecker` (`verifier/pkg/sourcereader/finality_checker.go:348`) picks the checker in this order: `SourceConfig.DisableFinalityChecker` selects the no-op checker; then a reporter selects `logPollerFinalityChecker`; otherwise the header-based checker.
- `logPollerFinalityChecker` reads only `FinalityViolated()`, which is true when the LogPoller's `Healthy()` returns `commontypes.ErrFinalityViolated`. It makes no RPC calls. The LogPoller clears its flag once it reconciles, so the checker latches the first violation. It logs `FINALITY VIOLATION DETECTED - reported by the log poller` and sets the finality-violated metric, and `handleFinalityViolation` disables the chain as before.
- A live recovery reset uses the same selection. While the LogPoller still reports a violation, the reset fails with `log poller still reports a finality violation` and the reader stays disabled.
- `chainaccess.FinalityViolationReporter` is injected per chain, not exposed by the reader, so reader decorators such as `observedSourceReader` cannot hide or fake it.
- Accepted risk: the flag is sampled once per poll. The backup poller re-declares a violation on its next run. A violation declared only by a LogPoller `Replay` can be cleared before a poll samples it. The startup load retries a replay that hits a violation, so the violation is re-declared on each retry while it persists. It is missed only if the LogPoller reconciles before a poll samples it.

## Startup load

The LogPoller resumes after its own newest stored block, not the verifier's checkpoint. Without a replay it would not refill a range the verifier resumes in, such as after `chain-statuses set-finalized-height` or on the first start with a new filter.

- `sourcereader.Service` calls `LoadFrom(startBlock)` on a reader that implements `chainaccess.SourceLoader`, after it initializes the start block (checkpoint + 1). Only the first call before `Close` counts. On `Close`, the service calls the reader's `Close`, logging a failure as a warning.
- `LoadFrom` starts a goroutine. Each attempt runs these steps:
  1. Registers the filter (10s timeout).
  2. Deletes the LogPoller's logs and blocks from the start block with `DeleteLogsAndBlocksAfter`, on every start, so everything after the checkpoint is fetched again.
  3. If that left the LogPoller with no blocks, anchors it with `SkipToBlock(startBlock)`, which saves `startBlock - 1` (the finalized checkpoint) as its last processed block. Skipped when the start block is below 2. Without the anchor, an empty LogPoller would start its next poll at the chain's finalized block. If the replay then failed, the blocks from the start block up to that point would never be indexed, and the reader would still read them.
  4. Calls `Replay` from the start block. A start block above the head tracker's latest block needs no replay.
- Failures are retried with backoff from 1s up to 1m, until the load succeeds or the reader closes.
- Until the load finishes, reads return `evm.ErrLogPollerNotReady`, which wraps `chainaccess.ErrSourceNotReady`. The service logs `Source not ready yet, waiting` at info instead of the `Error when querying logs` warning, and does not advance the checkpoint. `source_reader_state` still reports `poll_error`.
- `DeleteLogsAndBlocksAfter` is chain-wide: other LogPoller consumers on the chain lose logs after the start block until the replay refills them. This now happens on every start.
- Every restart replays from the checkpoint, normally about one finality depth of blocks.
- `observedSourceReader` implements `SourceLoader` and forwards `LoadFrom`, `Loaded`, and `Close`. Other `SourceReader` wrappers must do the same, or the load never starts and health never sees it.

## Load health

`chainaccess.SourceLoader` has a `Loaded() error` method. `LogPollerSourceReader.Loaded` returns `nil` once the load has finished and `evm.ErrLogPollerNotReady` until then.

- `sourcereader.Service.Ready` returns the `Loaded` error while the reader is loading, after the start-block check and before the finality-blocked check.
- When the start block is set, the service records the chain healthy only if the reader is already loaded. Before this change, it always recorded it healthy.
- If the reader was still loading at start, the first successful poll after the load finishes records the chain healthy. This happens only once, so it never overrides a later unhealthy state such as a disabled chain.
- A reader that is not a `SourceLoader` counts as loaded, so the RPC reader behaves as before.

## Filter lifecycle

`LogPollerSourceReader.Close` stops the startup routine and unregisters the reader's own filter (10s timeout). A failed unregister is logged and does not fail `Close`.

| Path | Result |
|---|---|
| UI or CLI job delete, JD cancel | The job closes and its filter is unregistered. |
| JD update, onramp change | The old job unregisters its filter; the new one registers its own and runs the startup load. |
| Node shutdown | Filters are unregistered. The next start registers them again and runs the startup load. Logs pruned in between are refilled by its replay. |
| Node crash | The filter stays. The next start re-registers it and runs the same startup load. |

Known limits: if a node crashes and the job is then removed while the node is down, its filter is left behind. Two jobs with the same `verifierID` and onramp share a filter, so closing one removes the other's. A duplicate `verifierID` on a node is already a misconfiguration.

## Compatibility & Requirements

- **Dependency bumps:** none.
- **Supported environments:** only the CL-mode EVM verifier with the LogPoller enabled uses the new reader. The standalone verifier and non-EVM readers do not change.
- **Log retention:** logs older than the 30-day filter retention can be pruned before the verifier reads them. The startup replay fetches them again from RPC, but they can be pruned again later.
- **Tests:** the devenv smoke test now checks that, in CL mode, at least one node has a `ccv-verifier - %` filter in `evm.log_poller_filters` (`build/devenv/tests/e2e/logpoller_in_use_test.go`).

## References

- Commits: `cba838c7` source reader log poller, `a112a7cf` finality violation from the LogPoller, `641f6887` startup replay, `7251722c` LogPoller finality checker, `0a9d92dd` behind-block error, `cdeee041` filter naming, `c22ba7d7` background startup load, `d3b8dbfc`/`5332a027` filter lifecycle, `ace9425f`/`c3e6abd6` injected finality reporters, `7b95ea4f` dedicated LogPoller reader, `9b604497` unconditional delete and anchor, `45f05ad1` blocks from the LogPoller, `3a90c49a` load health. `4c52b8ab` (CLI rewind) is superseded by the startup load.
- Prior changelog entries this builds on: `2026-09-29_source_reader_block_confirmation.md`, `2026-09-11_source_recovery.md`.
