# Message
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **ccip\_receive\_gas\_limit** | **Integer** | Gas limit reserved for the receiver&#39;s ccipReceive call on the destination chain. | [default to null] |
| **ccv\_and\_executor\_hash** | **String** | Commits to the CCVs and executor the message requested, 32 bytes hex-encoded. | [default to null] |
| **data** | **String** | The message payload. | [default to null] |
| **dest\_blob** | **String** | The destination-chain execution blob. | [default to null] |
| **dest\_chain\_selector** | **String** | CCIP selector of the destination chain, as a decimal string. See the schema description for why this is not a JSON number. | [default to null] |
| **execution\_gas\_limit** | **Integer** | Gas limit reserved for execution on the destination chain. | [default to null] |
| **finality** | **Integer** | The encoded finality requirement of the message. The low 16 bits are a block-confirmation depth; the high bits are flags. | [default to null] |
| **off\_ramp\_address** | **String** | Destination-chain offRamp that will deliver the message. | [default to null] |
| **on\_ramp\_address** | **String** | Source-chain onRamp that emitted the message. | [default to null] |
| **receiver** | **String** | Destination-chain account that will receive the message. | [default to null] |
| **sender** | **String** | Source-chain account that sent the message. | [default to null] |
| **sequence\_number** | **Long** | Per-lane sequence number of the message. | [default to null] |
| **source\_chain\_selector** | **String** | CCIP selector of the source chain, as a decimal string. See the schema description for why this is not a JSON number. | [default to null] |
| **token\_transfer** | [**TokenTransfer**](TokenTransfer.md) |  | [optional] [default to null] |
| **version** | **Integer** | CCIP message format version. | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

