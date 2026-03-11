package readers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestReadLimitedBody(t *testing.T) {
	tests := []struct {
		name       string
		body       io.Reader
		maxBytes   int
		wantLen    int
		wantErr    error
		wantAnyErr bool
	}{
		{
			name:     "returns body within limit",
			body:     bytes.NewReader([]byte("hello world")),
			maxBytes: 1024,
			wantLen:  11,
		},
		{
			name:     "returns body exactly at limit",
			body:     bytes.NewReader(make([]byte, 100)),
			maxBytes: 100,
			wantLen:  100,
		},
		{
			name:     "rejects body exceeding limit",
			body:     bytes.NewReader(make([]byte, 101)),
			maxBytes: 100,
			wantErr:  ErrResponseTooLarge,
		},
		{
			name:     "returns empty body within limit",
			body:     bytes.NewReader(nil),
			maxBytes: 100,
			wantLen:  0,
		},
		{
			name:       "rejects zero maxBytes",
			body:       bytes.NewReader(nil),
			maxBytes:   0,
			wantAnyErr: true,
		},
		{
			name:       "rejects negative maxBytes",
			body:       bytes.NewReader(nil),
			maxBytes:   -1,
			wantAnyErr: true,
		},
		{
			name:       "propagates reader error",
			body:       io.NopCloser(&failingReader{}),
			maxBytes:   1024,
			wantAnyErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := readLimitedBody(tt.body, tt.maxBytes)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			if tt.wantAnyErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, b, tt.wantLen)
		})
	}
}

func TestBuildRequestURL(t *testing.T) {
	messageID1 := protocol.Bytes32{0x1}
	messageID2 := protocol.Bytes32{0x2}

	r := &restReader{baseURL: "http://localhost:8080"}
	got := r.buildRequestURL([]protocol.Bytes32{messageID1, messageID2})

	expected := "http://localhost:8080/verifications?" + url.Values{"messageID": []string{messageID1.String() + "," + messageID2.String()}}.Encode()
	assert.Equal(t, expected, got)
}

func TestBuildRequestURLWithVersionedBaseURL(t *testing.T) {
	messageID := protocol.Bytes32{0x3}

	r := &restReader{baseURL: "http://localhost:8080/v1"}
	got := r.buildRequestURL([]protocol.Bytes32{messageID})

	expected := "http://localhost:8080/v1/verifications?" + url.Values{"messageID": []string{messageID.String()}}.Encode()
	assert.Equal(t, expected, got)
}

func TestGetVerificationsWithEmptyMessageIDsReturnsNilWithoutCallingAPI(t *testing.T) {
	reader := &restReader{
		baseURL:          "http://unused",
		maxResponseBytes: 1024,
		httpClient:       &http.Client{Timeout: time.Second},
		lggr:             logger.Test(t),
	}
	results, err := reader.GetVerifications(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, results)

	results, err = reader.GetVerifications(context.Background(), []protocol.Bytes32{})
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestGetVerificationsUsesTokenVerifierEndpoint(t *testing.T) {
	messageID := protocol.Bytes32{0xAA}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "/verifications", req.URL.Path)
		assert.Equal(t, messageID.String(), req.URL.Query().Get("messageID"))
		assert.Equal(t, jsonContentType, req.Header.Get("Accept"))
		assert.Equal(t, userAgent, req.Header.Get("User-Agent"))

		w.Header().Set("Content-Type", jsonContentType)
		_, _ = w.Write([]byte(`{"results":[],"errors":[]}`))
	}))
	defer ts.Close()

	reader := &restReader{
		baseURL:          ts.URL,
		maxResponseBytes: 1024,
		httpClient:       &http.Client{Timeout: time.Second},
		lggr:             logger.Test(t),
	}

	results, err := reader.GetVerifications(context.Background(), []protocol.Bytes32{messageID})
	require.NoError(t, err)
	assert.Empty(t, results)
}

type failingReader struct{}

func (f *failingReader) Read(_ []byte) (int, error) {
	return 0, assert.AnError
}
