# EVM source reader reads CCIPMessageSent logs from the Chainlink node's LogPoller

## Executive Summary

- In CL mode, the EVM source reader reads `CCIPMessageSent` logs from the node's LogPoller instead of `eth_getLogs`. The standalone verifier still reads logs over RPC.
- With a LogPoller, the latest, safe, and finalized blocks the reader reports are capped at the LogPoller's last processed block, so the verifier never advances past logs that are not indexed yet.
- A finality violation detected by the LogPoller now disables the source reader, through the new optional `chainaccess.FinalityViolationReporter` capability.
- On start, the source reader replays the LogPoller from its resume block before the first read, so a checkpoint rewound with `chain-statuses set-finalized-height`, or a newly registered filter, is refilled. The CLI does not change.
- No breaking changes for consumers. `evm.NewEVMSourceReader` takes a new trailing `*evm.LogPollerConfig` argument, but its only callers are in this repo and are updated. The Chainlink node calls `constructors.NewVerificationCoordinator`, whose signature does not change.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewEVMSourceReader` | signature-changed | `\bNewEVMSourceReader\(` | `integration/pkg/accessors/evm/evm_source_reader.go:72` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.SourceReader.FetchMessageSentEvents` | behavior-changed | `\.FetchMessageSentEvents\(` | `integration/pkg/accessors/evm/evm_source_reader.go:302` | [#log-source](#log-source) |
| `evm.SourceReader.LatestAndFinalizedBlock` | behavior-changed | `\.LatestAndFinalizedBlock\(` | `integration/pkg/accessors/evm/evm_source_reader.go:556` | [#block-capping](#block-capping) |
| `evm.SourceReader.LatestSafeBlock` | behavior-changed | `\.LatestSafeBlock\(` | `integration/pkg/accessors/evm/evm_source_reader.go:631` | [#block-capping](#block-capping) |
| `sourcereader.Service` finality check | behavior-changed | `sourcereader\.NewService\(` | `verifier/pkg/sourcereader/service.go:1040` | [#finality-violation-reporting](#finality-violation-reporting) |
| `sourcereader.Service` start | behavior-changed | `replaySourceIndex` | `verifier/pkg/sourcereader/service.go` | [#startup-replay](#startup-replay) |
| `evm.LogPollerConfig` | added | `\bLogPollerConfig\b` | `integration/pkg/accessors/evm/evm_source_reader.go:47` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.DefaultMessageSentLogRetention` | added | `\bDefaultMessageSentLogRetention\b` | `integration/pkg/accessors/evm/evm_source_reader.go:43` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.SourceReader.FinalityViolated` | added | `\.FinalityViolated\(` | `integration/pkg/accessors/evm/evm_source_reader.go:374` | [#finality-violation-reporting](#finality-violation-reporting) |
| `chainaccess.FinalityViolationReporter` | added | `\bFinalityViolationReporter\b` | `pkg/chainaccess/interfaces.go:68` | [#finality-violation-reporting](#finality-violation-reporting) |
| `evm.SourceReader.ReplayFrom` | added | `\.ReplayFrom\(` | `integration/pkg/accessors/evm/evm_source_reader.go` | [#startup-replay](#startup-replay) |
| `chainaccess.SourceReplayer` | added | `\bSourceReplayer\b` | `pkg/chainaccess/interfaces.go` | [#startup-replay](#startup-replay) |
| `chainaccess.ErrSourceFinalityViolated` | added | `\bErrSourceFinalityViolated\b` | `pkg/chainaccess/interfaces.go` | [#startup-replay](#startup-replay) |

## Breaking Changes

*No breaking changes.* `evm.NewEVMSourceReader` has a new last parameter, but its only callers (`integration/pkg/accessors/evm/factory.go` and `integration/pkg/constructors/committee_verifier.go`) are in this repo and are updated. The Chainlink node builds the reader through `constructors.NewVerificationCoordinator`, which is unchanged.

## NewEVMSourceReader signature

The constructor has a new last parameter, `lpCfg *evm.LogPollerConfig`, after `onCriticalInvariant`. A direct caller passes `nil` to read logs over RPC, as before.

```go
reader, err := evm.NewEVMSourceReader(/* ... */, onCriticalInvariant, &evm.LogPollerConfig{
	LogPoller:  chain.LogPoller(),
	VerifierID: cfg.VerifierID,
	Retention:  evm.DefaultMessageSentLogRetention,
})
```

`evm.LogPollerConfig` (`integration/pkg/accessors/evm/evm_source_reader.go:47`):

| Field | Meaning |
|---|---|
| `LogPoller` | The node's `logpoller.LogPoller`. `nil` or `logpoller.LogPollerDisabled` falls back to RPC, so a node with the LogPoller disabled needs no special case. |
| `VerifierID` | Required when `lpCfg` is not nil; otherwise the constructor returns `log poller verifierID is not set`. Used in the filter name. |
| `Retention` | Filter log retention. `evm.DefaultMessageSentLogRetention` is 30 days; it must exceed the longest expected verifier outage. |

When the LogPoller is enabled, the constructor registers a filter named `logpoller.FilterName(VerifierID, onRampAddress.Hex())` for the on-ramp address and the `CCIPMessageSent` topic. Registration has a 10 second timeout. A failure is returned as a constructor error.

## Log source

`FetchMessageSentEvents` reads from the LogPoller (`LogsWithSigs`) when one is configured, otherwise from `eth_getLogs`. The decoding and validation of logs are the same for both, in `parseMessageSentLogs`.

With a LogPoller:

- A `toBlock` of `0` means the LogPoller's last processed block (`LatestBlock`), not the chain head.
- If `fromBlock` is above that block, the call returns no events and no error.
- The block timestamp is copied from the LogPoller log, because `ToGethLog` drops it.

## Block capping

With a LogPoller, if its last processed block `P` is below the head tracker's block:

| Method | Result |
|---|---|
| `LatestAndFinalizedBlock` | `latest` is the header at `P`. `finalized` is also the header at `P` when `P` is below the finalized block. |
| `LatestSafeBlock` | The header at `P` when `P` is below the safe block. `nil` stays `nil`. |

The header at `P` comes from `GetBlocksHeaders`. A missing header is an error. Without a LogPoller, both methods behave as before.

## Finality violation reporting

- `chainaccess.FinalityViolationReporter` (`pkg/chainaccess/interfaces.go:68`) is an optional `SourceReader` capability with one method, `FinalityViolated() bool`.
- `evm.SourceReader.FinalityViolated` returns true when the LogPoller's `Healthy()` returns `commontypes.ErrFinalityViolated`. It returns false without a LogPoller.
- The metrics wrapper in `integration/pkg/sourcereader/observed_source_reader.go` forwards `FinalityViolated` to the reader it wraps. Other `SourceReader` wrappers must do the same, or the check does not run.
- `sourcereader.Service.checkFinality` asks the reader first. If it reports a violation, the service logs `Finality violation reported by the source reader` and runs the usual finality-violation handling, which disables the reader. `SourceConfig.DisableFinalityChecker` turns this check off too.

## Startup replay

The LogPoller resumes after its own newest stored block, not the verifier's checkpoint. Without a replay it would not refill a range the verifier resumes in, such as after `chain-statuses set-finalized-height` or the first start with a new filter.

- On start, if the chain is not disabled, the service records its resume block (checkpoint + 1). The first poll calls `chainaccess.SourceReplayer.ReplayFrom` with it before any read.
- `evm.SourceReader.ReplayFrom` calls the LogPoller's `Replay` and blocks until it finishes. It skips the call when the LogPoller has not reached the block yet, and replays when it has no blocks at all. It is a no-op without a LogPoller.
- A failed replay is retried on the next poll, and nothing is read until it succeeds.
- A replay that hits a finality violation returns `chainaccess.ErrSourceFinalityViolated`, and the service disables the chain.
- `Replay` deletes nothing, so other LogPoller consumers on the chain keep their data. It is safe on a running LogPoller.
- Every restart replays from the checkpoint, normally about one finality depth of blocks. A deep `set-finalized-height` rewind replays the whole range.
- A disabled chain does not replay. After a finality violation the checkpoint is `0`, and the operator sets a height and re-enables the chain before the next start.

## Compatibility & Requirements

- **Dependency bumps:** none.
- **Supported environments:** only the CL-mode EVM verifier uses the LogPoller. The standalone verifier and non-EVM readers do not change.
- **Log retention:** logs older than the 30-day filter retention can be pruned before the verifier reads them. The startup replay fetches them again from RPC, but they can be pruned again later.

## References

- Commits: `72ee0792` source reader log poller, `f1fb991c` tests, `17fb462c` lint fix, `8865f3c6` finality violation from the LogPoller. The CLI rewind from `f86b2af0` is replaced by the startup replay.
- Prior changelog entries this builds on: `2026-09-29_source_reader_block_confirmation.md`, `2026-09-11_source_recovery.md`.
