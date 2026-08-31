package policy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// testAPIKey and testSecret are a well-formed pair: the API key is a UUID and the secret is 32
// bytes hex-encoded, which is what the shared hmac package requires of both.
const (
	testAPIKey = "3f2b7c58-6d41-4a9e-8b0c-1d2e3f405162"
	testSecret = "6f1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f"
)

func testCredential() *hmac.ClientConfig {
	return &hmac.ClientConfig{APIKey: testAPIKey, Secret: testSecret}
}

func TestResolveCredential_AbsentIsNotAnError(t *testing.T) {
	// Authentication is optional, so a verifier with no credential anywhere has to start and
	// call the endpoint unauthenticated rather than fail.
	t.Setenv(APIKeyEnvVar, "")
	t.Setenv(SecretKeyEnvVar, "")

	cred, err := ResolveCredential(nil)
	require.NoError(t, err)
	assert.Nil(t, cred)
}

func TestResolveCredential_FromEnv(t *testing.T) {
	t.Setenv(APIKeyEnvVar, testAPIKey)
	t.Setenv(SecretKeyEnvVar, testSecret)

	cred, err := ResolveCredential(nil)
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, testAPIKey, cred.APIKey)
	assert.Equal(t, testSecret, cred.Secret)
}

func TestResolveCredential_FileWinsOverEnv(t *testing.T) {
	t.Setenv(APIKeyEnvVar, "11111111-1111-1111-1111-111111111111")
	t.Setenv(SecretKeyEnvVar, "1111111111111111111111111111111111111111111111111111111111111111")

	cred, err := ResolveCredential(&vsecrets.PolicyHookSecret{APIKey: testAPIKey, SecretKey: testSecret})
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, testAPIKey, cred.APIKey, "the secrets file must win, as it does for aggregator credentials")
}

func TestResolveCredential_Rejects(t *testing.T) {
	tests := []struct {
		name   string
		file   *vsecrets.PolicyHookSecret
		errHas string
	}{
		{
			// A half-supplied pair is a misconfiguration, never a silent downgrade to no
			// authentication: an operator who set one of the two meant to authenticate.
			name:   "api key without secret",
			file:   &vsecrets.PolicyHookSecret{APIKey: testAPIKey},
			errHas: "secret_key is missing",
		},
		{
			name:   "secret without api key",
			file:   &vsecrets.PolicyHookSecret{SecretKey: testSecret},
			errHas: "api_key is missing",
		},
		{
			name:   "api key is not a uuid",
			file:   &vsecrets.PolicyHookSecret{APIKey: "acme-verifier-1", SecretKey: testSecret},
			errHas: "api_key",
		},
		{
			name:   "secret is too short",
			file:   &vsecrets.PolicyHookSecret{APIKey: testAPIKey, SecretKey: "abcd"},
			errHas: "secret_key",
		},
		{
			name:   "secret is not hex",
			file:   &vsecrets.PolicyHookSecret{APIKey: testAPIKey, SecretKey: "not-hex-not-hex-not-hex-not-hex-x"},
			errHas: "secret_key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := ResolveCredential(tc.file)
			require.Error(t, err)
			assert.Nil(t, cred)
			assert.Contains(t, err.Error(), tc.errHas)
			assert.NotContains(t, err.Error(), testSecret, "an error an operator will log must never carry the secret")
		})
	}
}

// TestHTTPChecker_SignsRequest is the test the operator's side depends on: it recomputes the
// signature the way the published contract tells an endpoint to, and refuses the request if it
// does not match. A change to what the verifier signs fails here rather than in production
// against an endpoint that starts rejecting every call.
func TestHTTPChecker_SignsRequest(t *testing.T) {
	const path = "/v1/evaluate"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		apiKey := r.Header.Get(hmac.HeaderAuthorization)
		timestamp := r.Header.Get(hmac.HeaderTimestamp)
		signature := r.Header.Get(hmac.HeaderSignature)
		if apiKey != testAPIKey || timestamp == "" || signature == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// The timestamp is what makes a captured request unreplayable, so it has to be a
		// millisecond epoch an endpoint can compare against its own clock.
		ms, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || time.Since(time.UnixMilli(ms)) > time.Minute {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		stringToSign := hmac.GenerateStringToSign(
			http.MethodPost, r.URL.RequestURI(), hmac.ComputeBodyHash(body), apiKey, timestamp)
		if !hmac.ValidateSignature(stringToSign, signature, testSecret) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		_, _ = w.Write([]byte(`{"decision":"PASS"}`))
	}))
	defer srv.Close()

	checker, err := NewHTTPChecker(logger.Test(t), &Config{
		EndpointURL:        srv.URL + path,
		InsecureConnection: true,
	}, testCredential())
	require.NoError(t, err)

	verdict, err := checker.Evaluate(t.Context(), testRequest())
	require.NoError(t, err, "the endpoint rejected the verifier's own signature")
	assert.Equal(t, DecisionPass, verdict.Decision)
}

// An endpoint that requires authentication answers an unsigned call with 401, and the verifier
// has to read that as "verdict unknown" and retry. A misconfigured credential must never look
// like a rejection.
func TestHTTPChecker_UnauthenticatedAgainstAuthenticatedEndpointRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(hmac.HeaderSignature) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"decision":"PASS"}`))
	}))
	defer srv.Close()

	_, err := newTestChecker(t, srv, "").Evaluate(t.Context(), testRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

// No credential means no headers at all, so an endpoint that does not check them is unaffected
// by the feature existing.
func TestHTTPChecker_NoCredentialSendsNoAuthHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"decision":"PASS"}`))
	}))
	defer srv.Close()

	_, err := newTestChecker(t, srv, "").Evaluate(t.Context(), testRequest())
	require.NoError(t, err)
	assert.Empty(t, got.Get(hmac.HeaderAuthorization))
	assert.Empty(t, got.Get(hmac.HeaderTimestamp))
	assert.Empty(t, got.Get(hmac.HeaderSignature))
}

// The signature covers the request target, so an endpoint_url carrying a query signs it too.
// Getting this wrong would make every call to such an endpoint fail verification.
func TestSignRequest_CoversPathAndQuery(t *testing.T) {
	body := []byte(`{"message_id":"0xabc"}`)
	now := time.UnixMilli(1780000000000)

	for _, tc := range []struct{ url, wantTarget string }{
		{url: "https://policy.example.com", wantTarget: "/"},
		{url: "https://policy.example.com/v1/evaluate", wantTarget: "/v1/evaluate"},
		{url: "https://policy.example.com/v1/evaluate?tenant=acme", wantTarget: "/v1/evaluate?tenant=acme"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tc.url, nil)
			require.NoError(t, err)
			require.NoError(t, signRequest(req, testCredential(), body, now))

			want := hmac.GenerateStringToSign(
				http.MethodPost, tc.wantTarget, hmac.ComputeBodyHash(body), testAPIKey, "1780000000000")
			expected, err := hmac.ComputeHMAC(testSecret, want)
			require.NoError(t, err)

			assert.Equal(t, expected, req.Header.Get(hmac.HeaderSignature))
			assert.Equal(t, "1780000000000", req.Header.Get(hmac.HeaderTimestamp))
		})
	}
}
