# EVM source reader reads CCIPMessageSent logs from the Chainlink node's LogPoller

## Executive Summary

- In CL mode, the EVM source reader reads `CCIPMessageSent` logs from the node's LogPoller instead of `eth_getLogs`. The standalone verifier still reads logs over RPC.
- With a LogPoller, the latest, safe, and finalized blocks the reader reports are capped at the LogPoller's last processed block, so the verifier never advances past logs that are not indexed yet.
- A finality violation detected by the LogPoller now disables the source reader, through the new optional `chainaccess.FinalityViolationReporter` capability.
- `chain-statuses set-finalized-height` also rewinds the LogPoller in the same database transaction, and disables the chain when the rewind needs a manual replay.
- No breaking changes for consumers. `evm.NewEVMSourceReader` takes a new trailing `*evm.LogPollerConfig` argument, but its only callers are in this repo and are updated. The Chainlink node calls `constructors.NewVerificationCoordinator`, whose signature does not change.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.NewEVMSourceReader` | signature-changed | `\bNewEVMSourceReader\(` | `integration/pkg/accessors/evm/evm_source_reader.go:72` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.SourceReader.FetchMessageSentEvents` | behavior-changed | `\.FetchMessageSentEvents\(` | `integration/pkg/accessors/evm/evm_source_reader.go:302` | [#log-source](#log-source) |
| `evm.SourceReader.LatestAndFinalizedBlock` | behavior-changed | `\.LatestAndFinalizedBlock\(` | `integration/pkg/accessors/evm/evm_source_reader.go:556` | [#block-capping](#block-capping) |
| `evm.SourceReader.LatestSafeBlock` | behavior-changed | `\.LatestSafeBlock\(` | `integration/pkg/accessors/evm/evm_source_reader.go:631` | [#block-capping](#block-capping) |
| `sourcereader.Service` finality check | behavior-changed | `sourcereader\.NewService\(` | `verifier/pkg/sourcereader/service.go:1040` | [#finality-violation-reporting](#finality-violation-reporting) |
| `chainstatuses` `set-finalized-height` command | behavior-changed | `set-finalized-height` | `cli/chainstatuses/commands.go:69` | [#set-finalized-height-logpoller-rewind](#set-finalized-height-logpoller-rewind) |
| `evm.LogPollerConfig` | added | `\bLogPollerConfig\b` | `integration/pkg/accessors/evm/evm_source_reader.go:47` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.DefaultMessageSentLogRetention` | added | `\bDefaultMessageSentLogRetention\b` | `integration/pkg/accessors/evm/evm_source_reader.go:43` | [#newevmsourcereader-signature](#newevmsourcereader-signature) |
| `evm.SourceReader.FinalityViolated` | added | `\.FinalityViolated\(` | `integration/pkg/accessors/evm/evm_source_reader.go:374` | [#finality-violation-reporting](#finality-violation-reporting) |
| `chainaccess.FinalityViolationReporter` | added | `\bFinalityViolationReporter\b` | `pkg/chainaccess/interfaces.go:68` | [#finality-violation-reporting](#finality-violation-reporting) |
| `chainstatus.PostgresChainStatusStore.SetFinalizedBlockHeightWith` | added | `\bSetFinalizedBlockHeightWith\(` | `verifier/pkg/chainstatus/postgres.go:223` | [#setfinalizedblockheightwith](#setfinalizedblockheightwith) |
| `chainstatus.ErrTransactionRequired` | added | `\bErrTransactionRequired\b` | `verifier/pkg/chainstatus/postgres.go:22` | [#setfinalizedblockheightwith](#setfinalizedblockheightwith) |

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

## set-finalized-height LogPoller rewind

The LogPoller resumes from its own newest stored block, not from `finalized_block_height`. So `set-finalized-height` now also deletes the LogPoller's blocks and logs from `block-height + 1`, in the same transaction as the height update.

The rewind runs only when all of these are true. Otherwise the height is set as before, and the command prints the skip reason.

- The chain family is EVM.
- The store implements `SetFinalizedBlockHeightWith`.
- The `evm.log_poller_filters` table exists and has a filter whose name starts with `<verifier-id> - `.

The height must fit in an `int64` and be below `math.MaxInt64`. Otherwise the command fails and changes nothing.

| LogPoller state | Result |
|---|---|
| Has blocks above the height and at least one at or below it | Blocks and logs from `height + 1` deleted. |
| No blocks above the height | Nothing to rewind. |
| No blocks, or all blocks above the height | Blocks and logs from `height + 1` deleted, the chain is **disabled**, and a replay runbook (`chainlink blocks replay ...`, then `chain-statuses enable`) is printed. |

The delete is chain-wide, so every LogPoller consumer on that chain re-reads the deleted range. Operator details are in `cli/chainstatuses/README.md` and `docs/runbooks/remediating-stuck-or-dropped-messages.md`.

## SetFinalizedBlockHeightWith

```go
func (s *PostgresChainStatusStore) SetFinalizedBlockHeightWith(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	verifierID string,
	height *big.Int,
	also func(ctx context.Context, tx sqlutil.DataSource, txStore *PostgresChainStatusStore) error,
) error
```

- Sets the height, then runs `also` in the same transaction. If either fails, both are rolled back.
- `also` gets the transaction and a store bound to it. Use `txStore` inside `also`. The outer store runs outside the transaction and waits on the row lock.
- `also` may be `nil`. It is not called when no row matches.
- Returns `chainstatus.ErrTransactionRequired`, and changes nothing, when the store's `DataSource` cannot begin a transaction (for example, it is already a transaction).
- `ChainStatusStore` does not change. The CLI checks for this method with a type assertion.

## Compatibility & Requirements

- **Dependency bumps:** `github.com/scylladb/go-reflectx` is now a direct dependency in `go.mod`. `go.md` is regenerated.
- **Supported environments:** only the CL-mode EVM verifier uses the LogPoller. The standalone verifier and non-EVM readers do not change.
- **Log retention:** logs older than the 30-day filter retention can be pruned before the verifier reads them, so a longer outage or a deeper rewind may not be recoverable through the LogPoller.

## References

- Commits: `72ee0792` source reader log poller, `f1fb991c` tests, `17fb462c` lint fix, `f86b2af0` set-finalized-height rewind, `8865f3c6` finality violation from the LogPoller.
- Prior changelog entries this builds on: `2026-09-29_source_reader_block_confirmation.md`, `2026-09-11_source_recovery.md`.
