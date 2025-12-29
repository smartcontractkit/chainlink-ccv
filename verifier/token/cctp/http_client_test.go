package cctp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	httputil "github.com/smartcontractkit/chainlink-ccv/verifier/token/http"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/internal"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	testTxHash = "0x1234567890123456789012345678901234567890123456789012345678901234"
)

func TestGetMessages_Success(t *testing.T) {
	lggr := logger.Test(t)
	mockHTTPClient := &internal.MockHTTPClient{}

	client := &HTTPClientImpl{
		lggr:   lggr,
		client: mockHTTPClient,
	}

	ctx := context.Background()
	sourceDomainID := uint32(0)
	txHash := testTxHash

	// Create response
	responseData := Messages{
		Messages: []Message{
			{
				Message:     "0xabcd",
				EventNonce:  "123",
				Attestation: "0xdef",
				Status:      "complete",
			},
		},
	}
	responseJSON, _ := json.Marshal(responseData)

	// Setup mocks
	mockHTTPClient.On("Get", ctx, mock.Anything).Return(
		protocol.ByteSlice(responseJSON),
		httputil.Status(200),
		nil,
	)
	// Execute
	result, err := client.GetMessages(ctx, sourceDomainID, txHash)

	// Verify
	require.NoError(t, err)
	assert.Len(t, result.Messages, 1)
	assert.Equal(t, "0xabcd", result.Messages[0].Message)
	assert.Equal(t, attestationStatusSuccess, result.Messages[0].Status)

	mockHTTPClient.AssertExpectations(t)
}

func TestGetMessages_InvalidTransactionHash(t *testing.T) {
	lggr := logger.Test(t)
	mockHTTPClient := &internal.MockHTTPClient{}

	client := &HTTPClientImpl{
		lggr:   lggr,
		client: mockHTTPClient,
	}

	ctx := context.Background()
	sourceDomainID := uint32(0)

	testCases := []struct {
		name   string
		txHash string
		errMsg string
	}{
		{
			name:   "Empty transaction hash",
			txHash: "",
			errMsg: "transaction hash cannot be empty",
		},
		{
			name:   "Missing 0x prefix",
			txHash: "1234567890123456789012345678901234567890123456789012345678901234",
			errMsg: "invalid transaction hash format",
		},
		{
			name:   "Wrong length",
			txHash: "0x123456",
			errMsg: "invalid transaction hash format",
		},
		{
			name:   "Too long",
			txHash: "0x12345678901234567890123456789012345678901234567890123456789012345678",
			errMsg: "invalid transaction hash format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock to expect error status tracking (validation errors have empty Status)
			result, err := client.GetMessages(ctx, sourceDomainID, tc.txHash)

			// Verify
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
			assert.Empty(t, result.Messages)
		})
	}
}

func TestGetMessages_HTTPError(t *testing.T) {
	lggr := logger.Test(t)
	mockHTTPClient := &internal.MockHTTPClient{}

	client := &HTTPClientImpl{
		lggr:   lggr,
		client: mockHTTPClient,
	}

	ctx := context.Background()
	sourceDomainID := uint32(0)
	txHash := testTxHash

	// Setup mocks
	httpErr := errors.New("connection timeout")
	mockHTTPClient.On("Get", ctx, mock.Anything).Return(
		protocol.ByteSlice{},
		httputil.Status(0),
		httpErr,
	)
	// Execute
	result, err := client.GetMessages(ctx, sourceDomainID, txHash)

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http call failed")
	assert.Contains(t, err.Error(), "connection timeout")
	assert.Empty(t, result.Messages)

	mockHTTPClient.AssertExpectations(t)
}

func TestGetMessages_NonOKStatus(t *testing.T) {
	lggr := logger.Test(t)
	mockHTTPClient := &internal.MockHTTPClient{}

	client := &HTTPClientImpl{
		lggr:   lggr,
		client: mockHTTPClient,
	}

	ctx := context.Background()
	sourceDomainID := uint32(0)
	txHash := testTxHash

	testCases := []struct {
		name       string
		statusCode httputil.Status
		response   string
	}{
		{"Not Found", 404, `{"error":"not found"}`},
		{"Too Many Requests", 429, `{"error":"rate limited"}`},
		{"Internal Server Error", 500, `{"error":"server error"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks
			mockHTTPClient.On("Get", ctx, mock.Anything).Return(
				protocol.ByteSlice(tc.response),
				tc.statusCode,
				nil,
			).Once()
			// Execute
			result, err := client.GetMessages(ctx, sourceDomainID, txHash)

			// Verify
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "circle API returned status")
			assert.Empty(t, result.Messages)

			mockHTTPClient.AssertExpectations(t)
		})
	}
}

func TestGetMessages_ParseError(t *testing.T) {
	lggr := logger.Test(t)
	mockHTTPClient := &internal.MockHTTPClient{}

	client := &HTTPClientImpl{
		lggr:   lggr,
		client: mockHTTPClient,
	}

	ctx := context.Background()
	sourceDomainID := uint32(0)
	txHash := testTxHash

	// Setup mocks with invalid JSON
	invalidJSON := protocol.ByteSlice(`{invalid json}`)
	mockHTTPClient.On("Get", ctx, mock.Anything).Return(
		invalidJSON,
		httputil.Status(200),
		nil,
	)

	// Execute
	result, err := client.GetMessages(ctx, sourceDomainID, txHash)

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode json")
	assert.Empty(t, result.Messages)

	mockHTTPClient.AssertExpectations(t)
}

func TestGetMessages_URLEncoding(t *testing.T) {
	lggr := logger.Test(t)
	mockHTTPClient := &internal.MockHTTPClient{}

	client := &HTTPClientImpl{
		lggr:   lggr,
		client: mockHTTPClient,
	}

	ctx := context.Background()
	sourceDomainID := uint32(0)
	txHash := testTxHash

	responseData := Messages{Messages: []Message{}}
	responseJSON, _ := json.Marshal(responseData)

	// Setup mock to capture the actual path
	var capturedPath string
	mockHTTPClient.On("Get", ctx, mock.MatchedBy(func(path string) bool {
		capturedPath = path
		return true
	})).Return(
		protocol.ByteSlice(responseJSON),
		httputil.Status(200),
		nil,
	)

	// Execute
	_, err := client.GetMessages(ctx, sourceDomainID, txHash)

	// Verify
	require.NoError(t, err)
	assert.Contains(t, capturedPath, "v2/messages/0")
	assert.Contains(t, capturedPath, "transactionHash=0x")
	assert.Contains(t, capturedPath, txHash)

	mockHTTPClient.AssertExpectations(t)
}

func TestGetMessages_MetricsTracking(t *testing.T) {
	lggr := logger.Test(t)
	ctx := context.Background()
	sourceDomainID := uint32(0)
	txHash := testTxHash

	t.Run("Success path tracks success metrics", func(t *testing.T) {
		mockHTTPClient := &internal.MockHTTPClient{}

		client := &HTTPClientImpl{
			lggr:   lggr,
			client: mockHTTPClient,
		}

		responseData := Messages{Messages: []Message{}}
		responseJSON, _ := json.Marshal(responseData)

		mockHTTPClient.On("Get", ctx, mock.Anything).Return(
			protocol.ByteSlice(responseJSON),
			httputil.Status(200),
			nil,
		).Once()

		// Verify metrics called with success
		_, err := client.GetMessages(ctx, sourceDomainID, txHash)
		require.NoError(t, err)

		mockHTTPClient.AssertExpectations(t)
	})

	t.Run("Error path tracks error metrics", func(t *testing.T) {
		mockHTTPClient := &internal.MockHTTPClient{}

		client := &HTTPClientImpl{
			lggr:   lggr,
			client: mockHTTPClient,
		}

		mockHTTPClient.On("Get", ctx, mock.Anything).Return(
			protocol.ByteSlice{},
			httputil.Status(0),
			errors.New("http error"),
		).Once()

		// Verify metrics called with error
		_, err := client.GetMessages(ctx, sourceDomainID, txHash)
		assert.Error(t, err)

		mockHTTPClient.AssertExpectations(t)
	})

	t.Run("Metrics called exactly once per request", func(t *testing.T) {
		mockHTTPClient := &internal.MockHTTPClient{}

		client := &HTTPClientImpl{
			lggr:   lggr,
			client: mockHTTPClient,
		}

		responseData := Messages{Messages: []Message{}}
		responseJSON, _ := json.Marshal(responseData)

		mockHTTPClient.On("Get", ctx, mock.Anything).Return(
			protocol.ByteSlice(responseJSON),
			httputil.Status(200),
			nil,
		).Once()

		// Should be called exactly once
		_, err := client.GetMessages(ctx, sourceDomainID, txHash)
		require.NoError(t, err)

		mockHTTPClient.AssertExpectations(t)
	})
}

func TestParseResponseBody(t *testing.T) {
	t.Run("Valid: Empty messages array", func(t *testing.T) {
		jsonData := `{"messages": []}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		assert.Empty(t, result.Messages)
	})

	t.Run("Valid: Single complete message", func(t *testing.T) {
		jsonData := `{
			"messages": [{
				"message": "0xabcdef1234567890",
				"eventNonce": "12345",
				"attestation": "0x9876543210fedcba",
				"cctpVersion": 2,
				"status": "complete",
				"decodedMessage": {
					"sourceDomain": "0",
					"destinationDomain": "1",
					"nonce": "100",
					"sender": "0x1111111111111111111111111111111111111111",
					"recipient": "0x2222222222222222222222222222222222222222",
					"destinationCaller": "0x3333333333333333333333333333333333333333",
					"messageBody": "0xdeadbeef",
					"decodedMessageBody": {
						"burnToken": "0x4444444444444444444444444444444444444444",
						"mintRecipient": "0x5555555555555555555555555555555555555555",
						"amount": "1000000",
						"messageSender": "0x6666666666666666666666666666666666666666"
					}
				}
			}]
		}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		require.Len(t, result.Messages, 1)

		msg := result.Messages[0]
		assert.Equal(t, "0xabcdef1234567890", msg.Message)
		assert.Equal(t, "12345", msg.EventNonce)
		assert.Equal(t, "0x9876543210fedcba", msg.Attestation)
		assert.Equal(t, float64(2), msg.CCTPVersion)
		assert.Equal(t, attestationStatusSuccess, msg.Status)
		assert.Equal(t, "0", msg.DecodedMessage.SourceDomain)
		assert.Equal(t, "1000000", msg.DecodedMessage.DecodedMessageBody.Amount)
	})

	t.Run("Valid: Message with optional fields", func(t *testing.T) {
		jsonData := `{
			"messages": [{
				"message": "0xtest",
				"eventNonce": "100",
				"attestation": "0xabc",
				"status": "complete",
				"cctpVersion": 2,
				"decodedMessage": {
					"sourceDomain": "0",
					"destinationDomain": "1",
					"nonce": "50",
					"sender": "0x1111111111111111111111111111111111111111",
					"recipient": "0x2222222222222222222222222222222222222222",
					"destinationCaller": "0x3333333333333333333333333333333333333333",
					"messageBody": "0xbody",
					"minFinalityThreshold": "65",
					"finalityThresholdExecuted": "128",
					"decodedMessageBody": {
						"burnToken": "0x4444444444444444444444444444444444444444",
						"mintRecipient": "0x5555555555555555555555555555555555555555",
						"amount": "2000000",
						"messageSender": "0x6666666666666666666666666666666666666666",
						"maxFee": "10000",
						"feeExecuted": "5000",
						"expirationBlock": "1000000",
						"hookData": "0xhookdata123"
					}
				}
			}]
		}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		require.Len(t, result.Messages, 1)

		body := result.Messages[0].DecodedMessage.DecodedMessageBody
		assert.Equal(t, "10000", body.MaxFee)
		assert.Equal(t, "5000", body.FeeExecuted)
		assert.Equal(t, "1000000", body.ExpirationBlock)
		assert.Equal(t, "0xhookdata123", body.HookData)
	})

	t.Run("Edge: Empty strings for fields", func(t *testing.T) {
		jsonData := `{
			"messages": [{
				"message": "",
				"eventNonce": "",
				"attestation": "",
				"status": "",
				"cctpVersion": 0
			}]
		}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		require.Len(t, result.Messages, 1)

		msg := result.Messages[0]
		assert.Equal(t, "", msg.Message)
		assert.Equal(t, "", msg.EventNonce)
		assert.Equal(t, "", msg.Attestation)
		assert.Equal(t, "", string(msg.Status))
	})

	t.Run("Edge: Very long hex string", func(t *testing.T) {
		// Create a 10KB+ hex string
		longHex := "0x" + strings.Repeat("ab", 5000)
		jsonData := fmt.Sprintf(`{
			"messages": [{
				"message": "%s",
				"eventNonce": "1",
				"attestation": "0xshort",
				"status": "complete",
				"cctpVersion": 2
			}]
		}`, longHex)
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		require.Len(t, result.Messages, 1)
		assert.Equal(t, longHex, result.Messages[0].Message)
		assert.Len(t, result.Messages[0].Message, 10002) // "0x" + 10000 chars
	})

	t.Run("Edge: Extra unknown fields ignored", func(t *testing.T) {
		jsonData := `{
			"messages": [{
				"message": "0xtest",
				"eventNonce": "1",
				"attestation": "0xabc",
				"status": "complete",
				"cctpVersion": 2,
				"unknownField1": "should be ignored",
				"futureFeature": 999
			}],
			"extraTopLevel": "also ignored"
		}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		require.Len(t, result.Messages, 1)
		assert.Equal(t, "0xtest", result.Messages[0].Message)
	})

	t.Run("Invalid: Empty JSON object", func(t *testing.T) {
		jsonData := `{}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		assert.Nil(t, result.Messages) // Messages field not populated, so nil slice
	})

	t.Run("Invalid: Null messages field", func(t *testing.T) {
		jsonData := `{"messages": null}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		assert.Nil(t, result.Messages)
	})

	t.Run("Invalid: Wrong type for messages (string)", func(t *testing.T) {
		jsonData := `{"messages": "not an array"}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode json")
		assert.Empty(t, result.Messages)
	})

	t.Run("Invalid: Unclosed JSON", func(t *testing.T) {
		jsonData := `{"messages": [`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode json")
		assert.Empty(t, result.Messages)
	})

	t.Run("Invalid: Missing messages field", func(t *testing.T) {
		jsonData := `{"other": [], "data": "test"}`
		result, err := parseResponseBody(protocol.ByteSlice(jsonData))
		require.NoError(t, err)
		assert.Nil(t, result.Messages) // Field not present, so nil
	})
}
