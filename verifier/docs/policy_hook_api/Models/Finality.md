# Finality
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **block\_depth** | **Integer** | Required block confirmations when mode is blockDepth, capped by full finality. Zero when mode is finalized. | [default to null] |
| **mode** | **String** | blockDepth waits for the requested confirmations or full finality, whichever comes first. finalized waits for the finalized head, or the safe head when safe is true. | [default to null] |
| **safe** | **Boolean** | True only for a supported safe-head requirement, with mode finalized and block_depth zero. If the source chain has no safe head, the verifier waits for full finality instead. | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

