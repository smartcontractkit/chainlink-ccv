# Documentation for CCV Committee Verifier Policy Hook

<a name="documentation-for-api-endpoints"></a>
## Documentation for API Endpoints

All URIs are relative to *https://policy.example.com*

| Class | Method | HTTP request | Description |
|------------ | ------------- | ------------- | -------------|
| *DefaultApi* | [**policyEvaluate**](Apis/DefaultApi.md#policyEvaluate) | **POST** /v1/evaluate | Evaluate a message against the operator's policy |


<a name="documentation-for-models"></a>
## Documentation for Models

 - [EvaluateRequest](./Models/EvaluateRequest.md)
 - [EvaluateResponse](./Models/EvaluateResponse.md)
 - [Message](./Models/Message.md)
 - [TokenTransfer](./Models/TokenTransfer.md)


<a name="documentation-for-authorization"></a>
## Documentation for Authorization

<a name="HmacApiKey"></a>
### HmacApiKey

- **Type**: API key
- **API key parameter name**: authorization
- **Location**: HTTP header

<a name="HmacSignature"></a>
### HmacSignature

- **Type**: API key
- **API key parameter name**: x-authorization-signature-sha256
- **Location**: HTTP header

<a name="HmacTimestamp"></a>
### HmacTimestamp

- **Type**: API key
- **API key parameter name**: x-authorization-timestamp
- **Location**: HTTP header

