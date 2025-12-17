package lbtc

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	httputil "github.com/smartcontractkit/chainlink-ccv/verifier/token/http"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestGetMessages(t *testing.T) {
	hash1 := "0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf"
	hash2 := "0x27bf6eb2920da82a6a1294ceff503733c5a46a36d6d6c56a006f8720c399574b"
	hash3 := "0x5455ad825ac854ec2bfee200961d62ea57269bd248b782ed727ab33fd698e061"

	tests := []struct {
		name           string
		hashes         []string
		responseJSON   string
		httpStatus     int
		httpErr        error
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result []AttestationResponse)
	}{
		{
			name:   "single approved attestation",
			hashes: []string{hash1},
			responseJSON: `{
				"attestations": [{
					"message_hash": "` + hash1 + `",
					"attestation": "0xabcd",
					"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
				}]
			}`,
			httpStatus: 200,
			validateResult: func(t *testing.T, result []AttestationResponse) {
				require.Len(t, result, 1)
				assert.Equal(t, hash1, result[0].MessageHash)
				assert.Equal(t, AttestationStatusApproved, result[0].Status)
			},
		},
		{
			name:   "multiple approved attestations",
			hashes: []string{hash1, hash2, hash3},
			responseJSON: `{
				"attestations": [
					{
						"message_hash": "` + hash1 + `",
						"attestation": "0xdata1",
						"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
					},
					{
						"message_hash": "` + hash2 + `",
						"attestation": "0xdata2",
						"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
					},
					{
						"message_hash": "` + hash3 + `",
						"attestation": "0xdata3",
						"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
					}
				]
			}`,
			httpStatus: 200,
			validateResult: func(t *testing.T, result []AttestationResponse) {
				require.Len(t, result, 3)
				for i, att := range result {
					assert.Equal(t, []string{hash1, hash2, hash3}[i], att.MessageHash)
				}
			},
		},
		{
			name:   "mixed statuses",
			hashes: []string{hash1, hash2, hash3},
			responseJSON: `{
				"attestations": [
					{
						"message_hash": "` + hash1 + `",
						"attestation": "0xdata1",
						"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
					},
					{
						"message_hash": "` + hash2 + `",
						"status": "NOTARIZATION_STATUS_PENDING"
					},
					{
						"message_hash": "` + hash3 + `",
						"status": "NOTARIZATION_STATUS_FAILED"
					}
				]
			}`,
			httpStatus: 200,
			validateResult: func(t *testing.T, result []AttestationResponse) {
				require.Len(t, result, 3)
				assert.Equal(t, AttestationStatusApproved, result[0].Status)
				assert.Equal(t, AttestationStatusPending, result[1].Status)
				assert.Equal(t, AttestationStatusFailed, result[2].Status)
			},
		},
		{
			name:         "empty hashes and response",
			hashes:       []string{},
			responseJSON: `{"attestations": []}`,
			httpStatus:   200,
			validateResult: func(t *testing.T, result []AttestationResponse) {
				assert.Empty(t, result)
			},
		},
		{
			name:         "hash not found returns empty",
			hashes:       []string{hash1},
			responseJSON: `{"attestations": []}`,
			httpStatus:   200,
			validateResult: func(t *testing.T, result []AttestationResponse) {
				assert.Empty(t, result)
			},
		},
		{
			name:          "http error",
			hashes:        []string{hash1},
			httpErr:       errors.New("connection timeout"),
			expectError:   true,
			errorContains: "failed to post attestation request",
		},
		{
			name:   "api error response",
			hashes: []string{hash1},
			responseJSON: `{
				"code": 13,
				"message": "failed to get deposits by hash set: rpc error: code = InvalidArgument desc = invalid hash"
			}`,
			httpStatus:    500,
			expectError:   true,
			errorContains: "attestation request failed",
		},
		{
			name:          "invalid json response",
			hashes:        []string{hash1},
			responseJSON:  `{invalid json}`,
			httpStatus:    200,
			expectError:   true,
			errorContains: "failed to unmarshal attestation response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHTTPClient := &httputil.MockHTTPClient{}
			client := &HTTPClientImpl{
				lggr:   logger.Test(t),
				client: mockHTTPClient,
			}

			ctx := t.Context()
			messageHashes := make([]protocol.ByteSlice, len(tt.hashes))
			for i, h := range tt.hashes {
				messageHashes[i] = mustByteSliceFromHex(h)
			}

			mockHTTPClient.On("Post", ctx, "bridge/v1/deposits/getByHash", mock.Anything).Return(
				protocol.ByteSlice(tt.responseJSON),
				httputil.Status(tt.httpStatus),
				tt.httpErr,
			)

			result, err := client.GetMessages(ctx, messageHashes)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				tt.validateResult(t, result)
			}

			mockHTTPClient.AssertExpectations(t)
		})
	}
}

func TestGetMessages_RequestFormat(t *testing.T) {
	mockHTTPClient := &httputil.MockHTTPClient{}
	client := &HTTPClientImpl{
		lggr:   logger.Test(t),
		client: mockHTTPClient,
	}

	ctx := t.Context()
	messageHashes := []protocol.ByteSlice{
		mustByteSliceFromHex("0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf"),
		mustByteSliceFromHex("0x27bf6eb2920da82a6a1294ceff503733c5a46a36d6d6c56a006f8720c399574b"),
	}

	var capturedPath string
	var capturedPayload protocol.ByteSlice
	mockHTTPClient.On("Post", ctx, mock.MatchedBy(func(path string) bool {
		capturedPath = path
		return true
	}), mock.MatchedBy(func(payload protocol.ByteSlice) bool {
		capturedPayload = payload
		return true
	})).Return(
		protocol.ByteSlice(`{"attestations":[]}`),
		httputil.Status(200),
		nil,
	)

	_, err := client.GetMessages(ctx, messageHashes)
	require.NoError(t, err)

	assert.Equal(t, "bridge/v1/deposits/getByHash", capturedPath)

	var request BatchRequest
	require.NoError(t, json.Unmarshal(capturedPayload, &request))
	assert.Len(t, request.PayloadHashes, 2)
	assert.Equal(t, "0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf", request.PayloadHashes[0])
	assert.Equal(t, "0x27bf6eb2920da82a6a1294ceff503733c5a46a36d6d6c56a006f8720c399574b", request.PayloadHashes[1])

	mockHTTPClient.AssertExpectations(t)
}

func TestNewAttestationRequest(t *testing.T) {
	tests := []struct {
		name   string
		hashes []string
	}{
		{"empty slice", []string{}},
		{"single hash", []string{"0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf"}},
		{"multiple hashes", []string{
			"0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf",
			"0x27bf6eb2920da82a6a1294ceff503733c5a46a36d6d6c56a006f8720c399574b",
			"0x5455ad825ac854ec2bfee200961d62ea57269bd248b782ed727ab33fd698e061",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageHashes := make([]protocol.ByteSlice, len(tt.hashes))
			for i, h := range tt.hashes {
				messageHashes[i] = mustByteSliceFromHex(h)
			}
			request := NewBatchRequest(messageHashes)
			assert.Len(t, request.PayloadHashes, len(tt.hashes))
			for i, hash := range messageHashes {
				assert.Equal(t, hash.String(), request.PayloadHashes[i])
			}
		})
	}
}

func TestAttestationResponse_JSON(t *testing.T) {
	hash1 := "0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf"

	tests := []struct {
		name        string
		json        string
		expectError bool
		validate    func(t *testing.T, result BatchResponse)
	}{
		{
			name: "empty attestations",
			json: `{
				"attestations": []
			}`,
			validate: func(t *testing.T, result BatchResponse) {
				assert.Empty(t, result.Attestations)
			},
		},
		{
			name: "single approved attestation",
			json: `{
				"attestations": [{
					"message_hash": "` + hash1 + `",
					"attestation": "0xabcd",
					"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
				}]
			}`,
			validate: func(t *testing.T, result BatchResponse) {
				require.Len(t, result.Attestations, 1)
				assert.Equal(t, hash1, result.Attestations[0].MessageHash)
				assert.Equal(t, AttestationStatusApproved, result.Attestations[0].Status)
			},
		},
		{
			name: "error response",
			json: `{
				"code": 13,
				"message": "invalid hash"
			}`,
			validate: func(t *testing.T, result BatchResponse) {
				assert.Equal(t, 13, result.Code)
				assert.Contains(t, result.Message, "invalid hash")
			},
		},
		{
			name:        "invalid json",
			json:        `{invalid}`,
			expectError: true,
		},
		{
			name: "wrong type for attestations",
			json: `{
				"attestations": "not an array"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result BatchResponse
			err := json.Unmarshal(protocol.ByteSlice(tt.json), &result)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validate(t, result)
			}
		})
	}
}

func TestGetMessages_RealWorldResponses(t *testing.T) {
	tests := []struct {
		name         string
		hashes       []string
		responseJSON string
		httpStatus   int
		expectError  bool
		validate     func(t *testing.T, result []AttestationResponse)
	}{
		{
			name:   "single approved with long attestation data",
			hashes: []string{"0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf"},
			responseJSON: `{
				"attestations": [{
					"message_hash": "0x117f49bfccd85ce2d0ad3a2c9bc27af2abd43eed0cbaeb2ddf5098cbd6bb8bcf",
					"attestation": "0x0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000e45c70a5050000000000000000000000000000000000000000000000000000000000000038",
					"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
				}]
			}`,
			httpStatus: 200,
			validate: func(t *testing.T, result []AttestationResponse) {
				require.Len(t, result, 1)
				assert.NotEmpty(t, result[0].Data)
			},
		},
		{
			name:   "multiple approved batch",
			hashes: []string{"0xbca4f38f27d1aaec0d36ceda9990f3508f72aa44fa90371962bc23a6d7b6429d", "0x27bf6eb2920da82a6a1294ceff503733c5a46a36d6d6c56a006f8720c399574b"},
			responseJSON: `{
				"attestations": [
					{
						"message_hash": "0xbca4f38f27d1aaec0d36ceda9990f3508f72aa44fa90371962bc23a6d7b6429d",
						"attestation": "0x0040",
						"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
					},
					{
						"message_hash": "0x27bf6eb2920da82a6a1294ceff503733c5a46a36d6d6c56a006f8720c399574b",
						"attestation": "0x0041",
						"status": "NOTARIZATION_STATUS_SESSION_APPROVED"
					}
				]
			}`,
			httpStatus: 200,
			validate: func(t *testing.T, result []AttestationResponse) {
				require.Len(t, result, 2)
				for _, att := range result {
					assert.Equal(t, AttestationStatusApproved, att.Status)
				}
			},
		},
		{
			name:   "api error invalid hash",
			hashes: []string{"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			responseJSON: `{
				"code": 13,
				"message": "failed to get deposits by hash set: rpc error: code = InvalidArgument desc = invalid hash"
			}`,
			httpStatus:  500,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHTTPClient := &httputil.MockHTTPClient{}
			client := &HTTPClientImpl{
				lggr:   logger.Test(t),
				client: mockHTTPClient,
			}

			ctx := t.Context()
			messageHashes := make([]protocol.ByteSlice, len(tt.hashes))
			for i, h := range tt.hashes {
				messageHashes[i] = mustByteSliceFromHex(h)
			}

			mockHTTPClient.On("Post", ctx, "bridge/v1/deposits/getByHash", mock.Anything).Return(
				protocol.ByteSlice(tt.responseJSON),
				httputil.Status(tt.httpStatus),
				nil,
			)

			result, err := client.GetMessages(ctx, messageHashes)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tt.validate(t, result)
			}

			mockHTTPClient.AssertExpectations(t)
		})
	}
}

func mustByteSliceFromHex(s string) protocol.ByteSlice {
	bs, err := protocol.NewByteSliceFromHex(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex string: %v", err))
	}
	return bs
}
