# EvaluateRequest
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **block\_depth** | **Long** | How far the message&#39;s block sits below finalized_block_number. Zero when the message&#39;s block is the finalized head or newer, which is the case for a message that met its finality requirement against the safe head rather than the finalized one. | [default to null] |
| **fee\_token** | **String** | Source-chain asset used to pay the message fees. Omitted when the source reader or an older queued task does not supply it. Addresses are lowercase 0x-prefixed hex, left-padded to at least 32 bytes; longer addresses retain all bytes and leading zeros. An empty address is \&quot;0x\&quot;. A supplied all-zero address is preserved, including when it identifies a native fee asset. | [optional] [default to null] |
| **fee\_token\_amount** | **String** | Total fee in the fee asset&#39;s smallest unit, as a decimal string. Sums all emitted receipt fees, including verifier, token, executor and network fees. Omitted when receipts or any receipt amount are unavailable; a known zero fee is \&quot;0\&quot;. | [optional] [default to null] |
| **finalized\_block\_number** | **Long** | The source chain&#39;s finalized head at the moment the message met its finality requirement. It is fixed at that point, so a message that is retried reports the head as of the original decision rather than the current one. | [default to null] |
| **message** | [**Message**](Message.md) |  | [default to null] |
| **message\_id** | **String** | The CCIP message ID, 32 bytes hex-encoded with an 0x prefix. | [default to null] |
| **schema\_version** | **String** | The contract version of this request. Always \&quot;v1\&quot; for this release; an endpoint serving several verifier releases branches on it. | [default to null] |
| **source\_block\_number** | **Long** | The source-chain block the message was emitted in. | [default to null] |
| **source\_block\_timestamp** | **Date** | The source block&#39;s timestamp in UTC (RFC 3339), when available from the source event or a matching block header already fetched by the verifier. Omitted when unavailable, including for older queued tasks. Never substitutes the discovery or finality time and does not require an additional RPC. | [optional] [default to null] |
| **source\_tx\_hash** | **String** | Identifier of the source-chain transaction that emitted the message. It is the raw identifier bytes the source chain reported, hex-encoded with an 0x prefix, whatever the chain family&#39;s own convention is - a 32-byte EVM transaction hash and a 64-byte Solana signature both arrive here as hex, not as the chain&#39;s native rendering. An endpoint that wants to show or query the native form (base58 for Solana, for example) re-encodes these bytes itself, using source_chain_selector to know which family it is looking at. | [default to null] |
| **verifier\_id** | **String** | Identifies the committee verifier node making the call. | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

