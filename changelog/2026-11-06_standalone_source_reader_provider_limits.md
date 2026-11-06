# Standalone source reads: provider limits and stalled-chain health

## Executive Summary

- Verifier log chunks now span at most `MaxBlockRange` blocks, counting both ends; they previously spanned one block more.
- The EVM RPC reader carries node-TOML `LogBackfillBatchSize` and `RPCDefaultBatchSize` limits into standalone log and header queries.
- A verifier chain reports not ready when log scans or finality checks remain unsuccessful, even if head queries still succeed.
- No Go API is removed or changed in a breaking way.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `sourcereader.Service.getBlockRanges` | behavior-changed | `getBlockRanges\(` | `verifier/pkg/sourcereader/service.go` | [#scan-chunks](#scan-chunks) |
| `sourcereader.NewService` | behavior-changed | `sourcereader\.NewService\(` | `verifier/pkg/sourcereader/service.go` | [#scan-chunks](#scan-chunks) |
| `sourcereader.Service.readiness` | behavior-changed | `no complete log scan\|finality checks failing` | `verifier/pkg/sourcereader/service.go` | [#stalled-chain-readiness](#stalled-chain-readiness) |
| `evm.SourceReader.rpcLogs` | behavior-changed | `MaxLogBlockRange` | `integration/pkg/accessors/evm/evm_source_reader.go` | [#scan-chunks](#scan-chunks) |
| `chainaccess.LogBlockRangeLimiter` | added | `LogBlockRangeLimiter` | `pkg/chainaccess/interfaces.go` | [#scan-chunks](#scan-chunks) |
| `evm.SourceReaderParams.MaxLogBlockRange` | added | `SourceReaderParams\{` | `integration/pkg/accessors/evm/evm_source_reader.go` | [#scan-chunks](#scan-chunks) |

## Breaking Changes

*No breaking changes.* Tests that pin `FetchMessageSentEvents` chunk bounds need the new inclusive bounds.

## Migration Guide

1. A `chainaccess.SourceReader` wrapper should forward `MaxLogBlockRange`, as `observedSourceReader` does, or the verifier cannot see the reader's cap.
2. Operators mounting a node TOML change nothing. Lower `LogBackfillBatchSize` and `RPCDefaultBatchSize` values now reach the corresponding standalone reads.

## Scan chunks

`getBlockRanges` built `[from, from+MaxBlockRange]`, which contains `MaxBlockRange+1` blocks. Chunks are now `[from, from+MaxBlockRange-1]`; the last chunk remains open-ended because the LogPoller reader rejects an explicit bound beyond its processed height.

`NewService` narrows its span to `chainaccess.LogBlockRangeLimiter.MaxLogBlockRange()` when the reader reports a smaller limit. The EVM RPC reader reports the effective `LogBackfillBatchSize` and splits any wider bounded request into multiple `eth_getLogs` calls, failing the whole read if one chunk fails. The LogPoller reader reports no RPC cap. The default header batch of 25 is lowered to `RPCDefaultBatchSize`; an explicit `source_reader_header_fetch_batch_size` is preserved.

## Stalled chain readiness

Two timestamps join the successful-head-query clock: the last complete log scan and the last successful finality update. After `StalenessThreshold`, either failure makes that chain not ready. The coordinator exposes the named chain as degraded on `/health`; disabled chains remain exempt, and an operator rebuild does not count as a stalled normal scan.

## References

- Prior changelog entries: `2026-11-03_evm_node_chain_settings_parity.md`, `2026-09-17_robust_evm_config_conversion.md`
