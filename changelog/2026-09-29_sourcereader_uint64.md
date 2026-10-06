# Human Overview

Block numbers on the source-reading boundary are now `uint64` instead of `*big.Int`:

* `chainaccess.SourceReader.FetchMessageSentEvents(ctx, fromBlock, toBlock)` — both parameters are
  now `uint64`. A `toBlock` of `0` means "up to the latest block" (previously `nil`).
* `chainaccess.SourceReader.GetBlocksHeaders(ctx, blockNumbers)` — the input is now `[]uint64`
  (the returned map was already keyed by `uint64`).
* `protocol.Finality.IsMessageReady(msgBlock, latestBlock, latestSafeBlock, latestFinalizedBlock)` —
  all parameters are now `uint64`, and the method returns only `bool`: nil arguments are no longer
  representable, so `protocol.ErrNilBlock` is removed. A `latestSafeBlock` of `0` means the chain
  does not expose a safe head (previously `nil`), with the same fall-back-to-finality semantics.

`protocol.BlockHeader.Number` and `protocol.MessageSentEvent.BlockNumber` were already `uint64`, so
this change removes conversion ceremony rather than altering behavior. The motivation is the
multi-client verifier wire contract (`ccv.sourcereader.v1`), which carries block numbers as
`uint64`; aligning the Go interfaces keeps the future gRPC stub a thin adapter.

**Not changed on purpose:** `protocol.ChainStatusInfo.FinalizedBlockHeight` and the
`verifier/pkg/chainstatus` / `cli/chainstatuses` storage interfaces stay `*big.Int`. The batcher and
Postgres store distinguish "field absent" (nil, leave unchanged) from "height zero" (reset on
finality violation), and that tri-state cannot be flattened into a plain `uint64` without a sentinel
collision. Token amounts, gas limits, chain IDs, and ECDSA scalars also stay `*big.Int` — they are
not block numbers.

# Adopting the change

* Pass block numbers directly (`reader.FetchMessageSentEvents(ctx, 95, 0)`); drop
  `big.NewInt(...)` wrappers and `.Uint64()`/`.String()` unwraps.
* Replace a `nil` `toBlock` with `0`, and a `nil` safe block with `0`.
* `IsMessageReady` no longer returns an error — delete the `if err != nil` branch and the
  `ErrNilBlock` check.
* Implementers of `chainaccess.SourceReader` outside this repo (e.g. chainlink-ccip-solana) must
  update their method signatures and mock expectations when bumping the ccv dependency.
* `internal/mocks/mock_SourceReader.go` was updated by hand; regenerating with mockery produces the
  same result.
