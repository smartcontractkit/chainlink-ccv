# Policy hook fee metadata, source time, address encoding and decoded finality

## Executive Summary

- Hook requests expose `fee_token`, `fee_token_amount` and `source_block_timestamp` when available.
- All hook address fields share a chain-independent hex encoding with a minimum width of 32 bytes.
- `message.finality` becomes an object with `mode`, `block_depth` and `safe` instead of a packed integer.
- Normalization, fee totals and decoded finality are derived from the task when the request is
  built, not stored on it. No additional RPCs or changes to signed message bytes.
- The OpenAPI contract, binding models and rendered documentation describe the updated v1 payload.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `policy.NewEvaluateRequest` | signature-changed | `NewEvaluateRequest\(` | `verifier/pkg/policy/contract.go:70` | [Deriving the view](#deriving-the-published-view) |
| `policy.MessageV1.Finality` | behavior-changed | `\.Finality\b\|["']finality["']` | `verifier/pkg/policy/contract.go:127` | [Decoded finality](#decoded-finality) |
| Policy request address encoding | behavior-changed | `sender\|receiver\|ramp_address\|token_address\|pool_address\|fee_token` | `pkg/chainaccess/message_details.go:34` | [Address encoding](#address-encoding) |
| `policy.hexPadded` / `policy.totalFeeTokenAmount` | added | `func hexPadded\(` | `verifier/pkg/policy/contract.go` | [Deriving the view](#deriving-the-published-view) |
| `protocol.Finality.Requirement`, `FinalityRequirement`, `FinalityMode` | added | `\.Finality\b` | `protocol/finality.go:65` | [Decoded finality](#decoded-finality) |
| `protocol.MessageSentEvent.FeeToken`, `.BlockTimestamp` | added | `MessageSentEvent\{` | `protocol/common_types.go:365` | [Source metadata](#source-metadata) |
| `vtypes.VerificationTask.FeeToken`, `.SourceBlockTimestamp` | added | `VerificationTask\{` | `verifier/pkg/vtypes/types.go:18` | [Source metadata](#source-metadata) |
| `policy.EvaluateRequest.FeeToken`, `.FeeTokenAmount`, `.SourceBlockTimestamp` | added | `EvaluateRequest\b` | `verifier/pkg/policy/contract.go:70` | [Source metadata](#source-metadata) |
| `policy.FinalityV1` | added | `MessageV1\b` | `verifier/pkg/policy/contract.go:37` | [Decoded finality](#decoded-finality) |

## Breaking Changes

The v1 request changes `message.finality` from an integer to an object. Address strings shorter
than 32 bytes now receive left-zero padding. Hook endpoints consuming the earlier v1 shape need
updated models and address comparisons. The internal `protocol.Message` format is unchanged.

`policy.NewEvaluateRequest` keeps its single return value and now derives the published view
itself, so callers pass the task and nothing else. `protocol.MessageSentEvent` and
`vtypes.VerificationTask` carry no normalized copy of the message: it was always a pure function
of data those types already hold, and a stored copy could only drift from the message it
describes.

### Decoded finality

| Previous value | New `message.finality` |
|---|---|
| `0` | `{"mode":"finalized","block_depth":0,"safe":false}` |
| `N` in `1..65535` | `{"mode":"blockDepth","block_depth":N,"safe":false}` |
| `65536` | `{"mode":"finalized","block_depth":0,"safe":true}` |
| Unsupported flags or flag/depth combinations | `{"mode":"finalized","block_depth":0,"safe":false}` |

Readers use `protocol.Finality.Requirement()`, following `protocol.Finality.IsMessageReady`:
block confirmations are capped by full finality,
and a safe requirement falls back to full finality when the source chain has no safe head.
The top-level `block_depth` still reports observed depth at readiness; it is a separate value.

### Address encoding

Every non-empty address is lowercase `0x`-prefixed hex, left-padded to at least 32 bytes. This applies
to ramps, sender, receiver, token pool, source/destination token, token receiver and fee token.
Addresses longer than 32 bytes and their leading zeros are retained. Empty addresses remain `"0x"`.
The shared reader helper performs no chain-family lookup, truncation or native-address decoding. Byte
payloads, transaction identifiers and the original message used for signing keep their encoding.

## Migration Guide

1. Update endpoint models against `verifier/policy_hook_openapi_v1.yaml` and consume the decoded
   finality fields. The object uses `block_depth`, consistent with the rest of the hook contract.
2. Apply the same address padding to addresses used for comparisons, retaining the chain selector
   as part of their identity.
3. Treat missing fee metadata or source time as unavailable. Do not substitute zero or current time.
4. Source reader implementations can fill `protocol.MessageSentEvent.FeeToken` and `.BlockTimestamp`
   using their existing decoded event/block data. No reader interface signature changes are
   required, and readers do not build the normalized view.
5. Direct callers of `policy.NewEvaluateRequest` pass the task as before; it produces the
   published shape itself.

## New Features / Additions

### Source metadata

`fee_token` and `source_block_timestamp` travel from the shared source event through the durable
verification task. The existing adapter copies the decoded fee asset and a supplied log timestamp;
the generic source-reader service also reuses already-fetched latest/safe/finalized headers when
their number matches the event's block. It never substitutes a different block's time. A provider
that omits timestamps can therefore leave the field unavailable without adding RPCs.

The hook sends source time as UTC RFC 3339. Old queued tasks and readers without these fields
continue to work; unknown fields are omitted from the request. A known zero fee asset is preserved.
The reader computes `fee_token_amount` by summing every `ReceiptWithBlob.FeeTokenAmount`,
including network fees, using
arbitrary-precision arithmetic. The total is a decimal string; missing receipts or any missing
amount omit the total, while a known zero is `"0"`.

Transaction-origin lookup remains deferred. `sender` can be an application contract; the hook does
not infer an end-user identity or make transaction RPCs.

### Deriving the published view

The normalized view an endpoint sees — addresses padded to one width, the fee asset and total,
decoded finality — is written directly into the generated request model. `MessageV1` already is
that view, in the exact shape the endpoint receives, so there is no intermediate struct between
the message and the wire. `policy.hexPadded` owns the padding, `policy.totalFeeTokenAmount` the
receipt aggregation, and finality decoding stays on `protocol.Finality.Requirement`.

The padding rule belongs to the hook's published contract rather than to the protocol, so it
lives in the package that owns the OpenAPI spec that mandates it. It is applied on the way out,
producing a string, so nothing ever holds a slice that aliases the signed message.

`policy.NewEvaluateRequest` reads the task's `Message`, `ReceiptBlobs` and `FeeToken`, all of
which the task already holds, so nothing new is persisted and there is no second copy to keep in
step with the message it describes. The derivation is pure and RPC-free, so a task read back from
the queue after a restart produces the same request as the one that was queued.

Readers therefore keep returning raw decoded event data and nothing else. Metadata that genuinely
cannot be derived from the message — the fee asset, the source block timestamp — stays a field of
its own on the event and the task. Future transaction-origin metadata belongs there too; no such
lookup is added here.
