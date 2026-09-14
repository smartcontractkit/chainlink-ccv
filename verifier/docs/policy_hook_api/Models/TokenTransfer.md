# TokenTransfer
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **amount** | **String** | Transferred amount in the token&#39;s smallest unit, as a decimal string because it does not fit a JSON number. | [default to null] |
| **dest\_token\_address** | **String** | Destination-chain token address. Addresses are lowercase 0x-prefixed hex, left-padded to at least 32 bytes; longer addresses retain all bytes and leading zeros. An empty address is \&quot;0x\&quot;. | [default to null] |
| **extra\_data** | **String** | Pool-specific data carried with the transfer. | [default to null] |
| **source\_pool\_address** | **String** | Source-chain token pool the tokens were locked or burned in. Addresses are lowercase 0x-prefixed hex, left-padded to at least 32 bytes; longer addresses retain all bytes and leading zeros. An empty address is \&quot;0x\&quot;. | [default to null] |
| **source\_token\_address** | **String** | Source-chain token address. Addresses are lowercase 0x-prefixed hex, left-padded to at least 32 bytes; longer addresses retain all bytes and leading zeros. An empty address is \&quot;0x\&quot;. | [default to null] |
| **token\_receiver** | **String** | Destination-chain account receiving the tokens. Addresses are lowercase 0x-prefixed hex, left-padded to at least 32 bytes; longer addresses retain all bytes and leading zeros. An empty address is \&quot;0x\&quot;. | [default to null] |
| **version** | **Integer** | Token transfer format version. | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

