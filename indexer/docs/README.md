# Documentation for Indexer API

<a name="documentation-for-api-endpoints"></a>
## Documentation for API Endpoints

All URIs are relative to *http://localhost*

| Class | Method | HTTP request | Description |
|------------ | ------------- | ------------- | -------------|
| *DefaultApi* | [**messages**](Apis/DefaultApi.md#messages) | **GET** /v1/messages | Get messages |
*DefaultApi* | [**verifierResults**](Apis/DefaultApi.md#verifierResults) | **GET** /v1/verifierresults | Get verifier results |
*DefaultApi* | [**verifierResultsByMessageId**](Apis/DefaultApi.md#verifierResultsByMessageId) | **GET** /v1/verifierresults/{messageID} | Get message by ID |


<a name="documentation-for-models"></a>
## Documentation for Models

 - [ErrorResponse](./Models/ErrorResponse.md)
 - [Message](./Models/Message.md)
 - [MessageMetadata](./Models/MessageMetadata.md)
 - [MessageWithMetadata](./Models/MessageWithMetadata.md)
 - [TokenTransfer](./Models/TokenTransfer.md)
 - [VerifierResult](./Models/VerifierResult.md)
 - [VerifierResultMetadata](./Models/VerifierResultMetadata.md)
 - [VerifierResultWithMetadata](./Models/VerifierResultWithMetadata.md)


<a name="documentation-for-authorization"></a>
## Documentation for Authorization

All endpoints do not require authorization.
