# Policy hook fee metadata, source time, address encoding and decoded finality

## Executive Summary

- Hook requests expose `fee_token`, `fee_token_amount` and `source_block_timestamp` when available.
- All hook address fields share a chain-independent hex encoding with a minimum width of 32 bytes.
- `message.finality` becomes an object with `mode`, `block_depth` and `safe` instead of a packed integer.
- Readers supply normalization, fee totals and decoded finality through `protocol.MessageDetails`;
  policy serializes those values. No additional RPCs or changes to signed message bytes.
- The OpenAPI contract, binding models and rendered documentation describe the updated v1 payload.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `policy.NewEvaluateRequest` | signature-changed | `NewEvaluateRequest\(` | `verifier/pkg/policy/contract.go:70` | [Reader ownership](#reader-ownership) |
| `policy.MessageV1.Finality` | behavior-changed | `\.Finality\b\|["']finality["']` | `verifier/pkg/policy/contract.go:127` | [Decoded finality](#decoded-finality) |
| Policy request address encoding | behavior-changed | `sender\|receiver\|ramp_address\|token_address\|pool_address\|fee_token` | `pkg/chainaccess/message_details.go:34` | [Address encoding](#address-encoding) |
| `taskverifier.Processor.processJobs` | behavior-changed | `MessageDetails` | `verifier/pkg/taskverifier/processor.go:317` | [Reader ownership](#reader-ownership) |
| `protocol.MessageDetails` / `MessageSentEvent.MessageDetails` / `vtypes.VerificationTask.MessageDetails` | added | `MessageSentEvent\{\|VerificationTask\{` | `protocol/message_details.go:8` | [Reader ownership](#reader-ownership) |
| `chainaccess.NewMessageDetails` | added | `FetchMessageSentEvents\(` | `pkg/chainaccess/message_details.go:12` | [Reader ownership](#reader-ownership) |
| `protocol.Finality.Requirement`, `FinalityRequirement`, `FinalityMode` | added | `\.Finality\b` | `protocol/finality.go:65` | [Decoded finality](#decoded-finality) |
| `protocol.MessageSentEvent.FeeToken`, `.BlockTimestamp` | added | `MessageSentEvent\{` | `protocol/common_types.go:365` | [Source metadata](#source-metadata) |
| `vtypes.VerificationTask.FeeToken`, `.SourceBlockTimestamp` | added | `VerificationTask\{` | `verifier/pkg/vtypes/types.go:18` | [Source metadata](#source-metadata) |
| `policy.EvaluateRequest.FeeToken`, `.FeeTokenAmount`, `.SourceBlockTimestamp` | added | `EvaluateRequest\b` | `verifier/pkg/policy/contract.go:70` | [Source metadata](#source-metadata) |
| `policy.FinalityV1` | added | `MessageV1\b` | `verifier/pkg/policy/contract.go:37` | [Decoded finality](#decoded-finality) |

## Breaking Changes

The v1 request changes `message.finality` from an integer to an object. Address strings shorter
than 32 bytes now receive left-zero padding. Hook endpoints consuming the earlier v1 shape need
updated models and address comparisons. The internal `protocol.Message` format is unchanged.

`policy.NewEvaluateRequest` now returns `(EvaluateRequest, error)` and requires
`VerificationTask.MessageDetails`. The source/queue readers populate it before policy evaluation.
Direct callers must supply reader details and handle the error.

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
   using their existing decoded event/block data, and populate `.MessageDetails` through
   `chainaccess.NewMessageDetails`. No reader interface signature changes are required.
5. Direct callers of `policy.NewEvaluateRequest` must provide `task.MessageDetails` and handle its
   error return. Normal source/queue processing supplies the details automatically.

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

### Reader ownership

`protocol.MessageDetails` carries normalized addresses, the fee asset and total, and decoded
finality independently of the original `protocol.Message`. `chainaccess.NewMessageDetails` is the
shared reader helper; it owns padding and receipt aggregation and delegates finality decoding to
`protocol.Finality.Requirement`. Address arrays are copied so consumers of the view cannot mutate
the signed message. The types and helper have no dependency on policy or its generated API.

The concrete reader attaches details to each event. The source-reader service preserves them when
forming a `VerificationTask`; it uses the same helper if an older reader supplies none. The task
queue consumer also fills absent details on legacy jobs before invoking any verifier, without
additional RPCs. Already-persisted details are preserved, including unavailable fee fields.

Policy serializes these supplied values without normalization, receipt aggregation or bit decoding.
Missing details are a construction error; the gate retries without contacting the endpoint or
signing. This catches callers that bypass the reader boundary without silently screening a
different set of addresses. Future transaction-origin metadata must also be supplied by readers;
no such lookup is added here.
