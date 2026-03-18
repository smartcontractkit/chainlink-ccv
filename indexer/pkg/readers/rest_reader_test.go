package readers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"
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

type failingReader struct{}

func (f *failingReader) Read(_ []byte) (int, error) {
	return 0, assert.AnError
}

func TestRestReader_GetVerifications_404_ReturnsEmptyMapAndNoError(t *testing.T) {
	messageID := protocol.Bytes32{1, 2, 3}
	messageIDHex := messageID.String()
	body := `{"results": [], "errors": ["message not found: ` + messageIDHex + `"]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	lggr, err := logger.New()
	require.NoError(t, err)

	rr := NewRestReader(RestReaderConfig{
		BaseURL:          server.URL,
		RequestTimeout:   0,
		MaxResponseBytes: 1024,
		HTTPClient:       server.Client(),
		Logger:           lggr,
	})

	result, err := rr.GetVerifications(context.Background(), []protocol.Bytes32{messageID})
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestRestReader_GetVerifications_404_MalformedBody_ReturnsEmptyMapAndNoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	lggr, err := logger.New()
	require.NoError(t, err)

	rr := NewRestReader(RestReaderConfig{
		BaseURL:          server.URL,
		RequestTimeout:   0,
		MaxResponseBytes: 1024,
		HTTPClient:       server.Client(),
		Logger:           lggr,
	})

	messageID := protocol.Bytes32{1, 2, 3}
	result, err := rr.GetVerifications(context.Background(), []protocol.Bytes32{messageID})
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestRestReader_GetVerifications_404_DoesNotOpenCircuitBreaker(t *testing.T) {
	messageID := protocol.Bytes32{1, 2, 3}
	messageIDHex := messageID.String()
	body := `{"results": [], "errors": ["message not found: ` + messageIDHex + `"]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	lggr, err := logger.New()
	require.NoError(t, err)

	rr := NewRestReader(RestReaderConfig{
		BaseURL:          server.URL,
		RequestTimeout:   0,
		MaxResponseBytes: 1024,
		HTTPClient:       server.Client(),
		Logger:           lggr,
	})

	ctx := context.Background()
	ids := []protocol.Bytes32{messageID}
	for i := 0; i < 6; i++ {
		// We don't care about the result we expect the circuit breaker to remain closed at the end of the test
		rr.GetVerifications(ctx, ids)
		if i < 5 {
			time.Sleep(250 * time.Millisecond)
		}
	}

	assert.NotEqual(t, circuitbreaker.OpenState, rr.GetCircuitBreakerState(),
		"404 responses must not count as failures; circuit breaker should remain closed")
}
