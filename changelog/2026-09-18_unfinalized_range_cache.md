# Cache the unfinalized block range to stop re-reading it every poll

## Executive Summary

- The verifier's source reader no longer re-queries logs for the whole unfinalized block range on every poll; it reads only blocks the head advanced by, and re-reads everything only when the source reader reports a reorg.
- Chains with fast blocks and slow finality (an Arbitrum-shaped chain has ~4,000 unfinalized blocks) were issuing ~40 `eth_getLogs` calls every 2s poll to re-scan blocks whose contents could not have changed.
- Affects `verifier/pkg/sourcereader.Service`, the EVM source reader in `integration/pkg/accessors/evm`, `pkg/chainaccess` (two new optional interfaces), and `verifier/pkg/vtypes.MetricLabeler` (one new method).
- Adds an optional, per-chain-family capability: readers that cannot prove the unfinalized range is unchanged keep the previous behaviour unchanged. One breaking change for downstream implementers of `vtypes.MetricLabeler`.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `vtypes.MetricLabeler` | signature-changed | `vtypes\.MetricLabeler\b` | `verifier/pkg/vtypes/interfaces.go:171` | [#metriclabeler-gains-incrementunfinalizedrangerereads](#metriclabeler-gains-incrementunfinalizedrangerereads) |
| `chainaccess.UnfinalizedRangeTracker` | added | `UnfinalizedRangeChanged\(` | `pkg/chainaccess/interfaces.go:71` | [#unfinalizedrangetracker](#unfinalizedrangetracker) |
| `chainaccess.SourceReaderUnwrapper` | added | `\bUnwrap\(\) SourceReader` | `pkg/chainaccess/interfaces.go:81` | [#sourcereaderunwrapper-and-decorators](#sourcereaderunwrapper-and-decorators) |
| `chainaccess.AsUnfinalizedRangeTracker` | added | `AsUnfinalizedRangeTracker\(` | `pkg/chainaccess/interfaces.go:92` | [#sourcereaderunwrapper-and-decorators](#sourcereaderunwrapper-and-decorators) |
| `evm.SourceReader.UnfinalizedRangeChanged` | added | `UnfinalizedRangeChanged\(` | `integration/pkg/accessors/evm/evm_source_reader.go:168` | [#evm-implementation](#evm-implementation) |
| `sourcereader.Service` log-query range | behavior-changed | `FetchMessageSentEvents\(` | `verifier/pkg/sourcereader/service.go:489` | [#log-query-window](#log-query-window) |
| `SourceReader.FetchMessageSentEvents` nil `toBlock` | behavior-changed | `FetchMessageSentEvents\(` | `verifier/pkg/sourcereader/service.go:315` | [#toblock-is-now-always-explicit](#toblock-is-now-always-explicit) |

## Breaking Changes

### MetricLabeler gains IncrementUnfinalizedRangeRereads

- **What changed:** `verifier/pkg/vtypes.MetricLabeler` gained a method.
- **Before:** the interface had no chain-tail metric.
- **After:** `IncrementUnfinalizedRangeRereads(ctx context.Context)` is required. It counts polls forced to re-read the whole unfinalized range.
- **Why:** the reread rate is the only signal that tells an operator whether the cache is saving anything on a given chain. Above roughly one reread per five polls the change is a net RPC *increase*, so it has to be observable.
- **Who is affected:** any downstream type implementing `vtypes.MetricLabeler` directly. In-repo implementations (`VerifierMetricLabeler`, `FakeVerifierMetricLabeler`, `NoopMetricLabeler`, generated mocks) are already updated.

## Migration Guide

1. Add the method to any custom `vtypes.MetricLabeler` implementation:

```go
// After
func (m *myMetricLabeler) IncrementUnfinalizedRangeRereads(ctx context.Context) {
	m.rereads.Add(ctx, 1, metric.WithAttributes(m.attrs...))
}
```

2. Regenerate mocks if you generate your own: `just mock`.

3. If you wrap `chainaccess.SourceReader` in a decorator, implement `Unwrap` or the wrapped reader's
   optional capabilities become invisible. See [#sourcereaderunwrapper-and-decorators](#sourcereaderunwrapper-and-decorators).

4. No action is needed for non-EVM source readers: they do not implement
   `UnfinalizedRangeTracker` and keep the previous full-range read.

## New Features / Additions

### UnfinalizedRangeTracker

An optional `SourceReader` capability in `pkg/chainaccess/interfaces.go`:

```go
type UnfinalizedRangeTracker interface {
	UnfinalizedRangeChanged(ctx context.Context, latest, finalized *protocol.BlockHeader) (bool, error)
}
```

`false` means every block the reader has already vouched for is unchanged, so the caller need only
read blocks above the previously observed head. `true`, and any error, mean re-read the whole
unfinalized range. Implement it only for chain families where block headers commit to their
ancestry; the verifier falls back to the previous behaviour when it is absent.

### SourceReaderUnwrapper and decorators

A decorator that embeds the `chainaccess.SourceReader` *interface* promotes only that interface's
methods, so a type assertion on the wrapper cannot see optional capabilities of the reader
underneath. `integration/pkg/sourcereader.observedSourceReader` is exactly that shape, and both
production wiring paths (`cmd/verifier/servicefactory.go:95`,
`integration/pkg/constructors/committee_verifier.go:151`) wrap the EVM reader before the verifier
sees it. Left unhandled, the cache would silently never engage.

Resolve capabilities through the helper rather than asserting directly:

```go
// Before
tracker, ok := reader.(chainaccess.UnfinalizedRangeTracker)
```

```go
// After — walks SourceReaderUnwrapper decorators, depth-bounded against a cyclic Unwrap
tracker, ok := chainaccess.AsUnfinalizedRangeTracker(reader)
```

Any decorator wrapping a `SourceReader` should implement `Unwrap() SourceReader`.

### EVM implementation

`integration/pkg/accessors/evm/chain_tail.go` caches the hash-linked headers from the finalized
block up to the latest head, maintaining the invariant that every stored header's `ParentHash`
equals the stored header below it. That makes one link check at the head sufficient to prove the
entire range is unchanged: a block hash commits to its whole ancestry, so a reorg at any depth
breaks the link from the new head down to the anchor — including a reorg that happened and
re-extended entirely between two polls.

On a broken link the cache is rebuilt over `[finalized, latest]` and the caller re-reads all of it.
A head that moves backwards to a height whose stored hash still matches is treated as RPC node lag,
not a reorg, and the cache is kept.

### Log query window

`Service.queryWindow` (`verifier/pkg/sourcereader/service.go:489`) derives the per-poll log range:

| Reader verdict | Range read |
|---|---|
| unchanged | `(lastReadBlock, latest]` |
| changed, or tracker error, or no tracker | `[min(checkpoint, finalized), latest]` |

`Service.lastReadBlock` tracks how far logs have been read on the chain as currently observed. It
lags the verified range when a log chunk fails mid-poll, so a partial read is retried rather than
skipped, and it moves *backwards* when a reorg rewinds the head — otherwise blocks re-mined at
heights already read would never be queried again.

Reorg reconciliation is unchanged in substance but now runs against the actually-queried window:
`addToPendingQueueHandleReorg` drops pending and sent tasks inside `[fromBlock, toBlock]` that did
not reappear and records them in `ReorgTracker`, which forces those sequence numbers to full
finality regardless of their configured finality. Because a non-reorg poll's window covers only new
blocks, older pending tasks are no longer candidates for removal.

### toBlock is now always explicit

`Service.getBlockRanges` no longer emits a `nil` `toBlock` for the final chunk. Previously the last
chunk was bounded by whatever `latest` the answering RPC node held, which can differ from the head
the range was computed against. `SourceReader.FetchMessageSentEvents` still accepts a nil `toBlock`;
the verifier simply never passes one.

## Compatibility & Requirements

- **New metric:** `verifier_source_reader_unfinalized_range_rereads` (counter, per source chain).
- **Feature flags / rollout:** none. The capability is enabled by presence of the interface, so it
  is active for EVM chains as soon as this ships. There is no operator kill switch; disabling it
  would require removing `UnfinalizedRangeChanged` from the EVM reader.
- **Expected RPC impact:** on an Arbitrum-shaped chain (0.25s blocks, ~4,000 unfinalized blocks,
  2s poll, `MaxBlockRange` 100) requests per poll fall from ~44 to ~6. On chains whose block time
  is at or above the poll interval the saving is small, because the three per-poll head calls
  dominate. A reorg poll costs ~204 requests, so break-even is a reread rate near one poll in five.

## References

- Prior changelog entries this builds on: `2026-09-13_resilient_reader_config.md`
