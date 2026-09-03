# EvaluateResponse
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **decision** | **String** | PASS signs and attests the message. FAIL drops it — it is never attested and never auto-executed, and recovery needs an operator to replay it, by rescheduling the archived job with the verifier CLI or by rewinding the verifier checkpoint. PASS is matched exactly; FAIL is matched case-insensitively, because reading a verdict as unusable only causes a retry while reading one as PASS causes a signature.  HOLD is reserved and not implemented by this release. It is listed here so that implementing it later is an additive change rather than a breaking one for an endpoint that validates responses strictly against this enum. Do not return it: a verifier reads it as \&quot;verdict unknown\&quot; and retries the message until the task queue&#39;s deadline. To hold a message for review today, answer FAIL and replay the message once the review clears.  | [default to null] |
| **message\_id** | **String** | Echo of the request&#39;s message_id. Recommended, but optional and not in the required list, because it is a safety net rather than part of the verdict and requiring it would fail an otherwise correct endpoint that omits it. Nothing else in this response ties the verdict to the message it answers, so echoing the ID lets the verifier refuse a verdict that reached it for a different message, which is what a shared cache or a proxy in front of the endpoint can produce. A mismatch is an error and retries; omitting the field skips the check. Compared case-insensitively. | [optional] [default to null] |
| **reason** | **String** | Optional explanation of a FAIL. The verifier logs it and never signs it. Values longer than 256 characters are truncated in logs. | [optional] [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

