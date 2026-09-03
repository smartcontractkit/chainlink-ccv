package hmac

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHTTPAPIKey = "3f2b7c58-6d41-4a9e-8b0c-1d2e3f405162"
	testHTTPSecret = "6f1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f"
)

// A server verifies a request by recomputing the string from what it received, so the request
// target the client signs has to be exactly the one that arrives, query string included.
func TestSignHTTPRequest_SignsMethodTargetAndBody(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	now := time.UnixMilli(1780000000000)
	cfg := &ClientConfig{APIKey: testHTTPAPIKey, Secret: testHTTPSecret}

	for _, tc := range []struct{ url, wantTarget string }{
		{url: "https://example.com", wantTarget: "/"},
		{url: "https://example.com/v1/evaluate", wantTarget: "/v1/evaluate"},
		{url: "https://example.com/v1/evaluate?tenant=acme", wantTarget: "/v1/evaluate?tenant=acme"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tc.url, nil)
			require.NoError(t, err)
			require.NoError(t, SignHTTPRequest(req, cfg, body, now))

			want := GenerateStringToSign(
				http.MethodPost, tc.wantTarget, ComputeBodyHash(body), testHTTPAPIKey, "1780000000000")
			assert.True(t, ValidateSignature(want, req.Header.Get(HeaderSignature), testHTTPSecret))
			assert.Equal(t, testHTTPAPIKey, req.Header.Get(HeaderAuthorization))
			assert.Equal(t, "1780000000000", req.Header.Get(HeaderTimestamp))
		})
	}
}

func TestSignHTTPRequest_Rejects(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com", nil)
	require.NoError(t, err)

	assert.Error(t, SignHTTPRequest(nil, &ClientConfig{APIKey: testHTTPAPIKey, Secret: testHTTPSecret}, nil, time.Now()))
	assert.Error(t, SignHTTPRequest(req, nil, nil, time.Now()))

	// A secret that is not usable as an HMAC key must fail loudly rather than leave the request
	// unsigned and the caller unaware.
	err = SignHTTPRequest(req, &ClientConfig{APIKey: testHTTPAPIKey, Secret: "not-hex"}, nil, time.Now())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not-hex", "an error a caller will log must not carry the secret")
}
