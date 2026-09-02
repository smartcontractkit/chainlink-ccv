# DefaultApi

All URIs are relative to *https://policy.example.com*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**policyEvaluate**](DefaultApi.md#policyEvaluate) | **POST** /v1/evaluate | Evaluate a message against the operator&#39;s policy |


<a name="policyEvaluate"></a>
# **policyEvaluate**
> EvaluateResponse policyEvaluate(EvaluateRequest)

Evaluate a message against the operator&#39;s policy

    Evaluate one CCIP message and return a binary verdict.  The operator configures a base URL as the verifier&#39;s policy_hook.base_url, and the verifier POSTs to that base with this operation&#39;s path appended. A base may carry a path prefix, so an endpoint behind a gateway that routes on one is configured as \&quot;https://acme.example/compliance\&quot; and serves \&quot;/compliance/v1/evaluate\&quot;. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **EvaluateRequest** | [**EvaluateRequest**](../Models/EvaluateRequest.md)|  | |

### Return type

[**EvaluateResponse**](../Models/EvaluateResponse.md)

### Authorization

[HmacApiKey](../README.md#HmacApiKey), [HmacTimestamp](../README.md#HmacTimestamp), [HmacSignature](../README.md#HmacSignature)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

