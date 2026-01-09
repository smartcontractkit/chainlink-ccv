# DefaultApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**messages**](DefaultApi.md#messages) | **GET** /v1/messages |  |
| [**verifierResults**](DefaultApi.md#verifierResults) | **GET** /v1/verifierresults |  |
| [**verifierResultsByMessageId**](DefaultApi.md#verifierResultsByMessageId) | **GET** /v1/verifierresults/{messageID} |  |


<a name="messages"></a>
# **messages**
> messages(sourceChainSelectors, destChainSelectors, start, end, limit, offset)



    Get messages

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **sourceChainSelectors** | [**List**](../Models/Long.md)| Source chain selectors to filter results by. If empty, results from all source chains will be returned. | [optional] [default to null] |
| **destChainSelectors** | [**List**](../Models/Long.md)| Destination chain selectors to filter results by. If empty, results from all destination chains will be returned. | [optional] [default to null] |
| **start** | **Long**| Start timestamp (in milliseconds) to filter results by. If not provided, defaults to 0. | [optional] [default to null] |
| **end** | **Long**| End timestamp (in milliseconds) to filter results by. If not provided, defaults to the current time. | [optional] [default to null] |
| **limit** | **Long**| Maximum number of results to return. If not provided, defaults to 100. | [optional] [default to null] |
| **offset** | **Long**| Number of results to skip before starting to return results. If not provided, defaults to 0. | [optional] [default to null] |

### Return type

null (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="verifierResults"></a>
# **verifierResults**
> verifierResults(sourceChainSelectors, destChainSelectors, start, end, limit, offset)



    Get verifier results

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **sourceChainSelectors** | [**List**](../Models/Long.md)| Source chain selectors to filter results by. If empty, results from all source chains will be returned. | [optional] [default to null] |
| **destChainSelectors** | [**List**](../Models/Long.md)| Destination chain selectors to filter results by. If empty, results from all destination chains will be returned. | [optional] [default to null] |
| **start** | **Long**| Start timestamp (in milliseconds) to filter results by. If not provided, defaults to 0. | [optional] [default to null] |
| **end** | **Long**| End timestamp (in milliseconds) to filter results by. If not provided, defaults to the current time. | [optional] [default to null] |
| **limit** | **Long**| Maximum number of results to return. If not provided, defaults to 100. | [optional] [default to null] |
| **offset** | **Long**| Number of results to skip before starting to return results. If not provided, defaults to 0. | [optional] [default to null] |

### Return type

null (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="verifierResultsByMessageId"></a>
# **verifierResultsByMessageId**
> verifierResultsByMessageId(messageID)



    Get message by ID

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **messageID** | **String**|  | [default to null] |

### Return type

null (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

