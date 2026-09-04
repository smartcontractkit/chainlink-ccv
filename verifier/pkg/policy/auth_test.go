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
	// Authentication is optional, so a verifier with no credential has to start and call the
	// endpoint unauthenticated rather than fail. An operator who wants the absence to be fatal
	// sets require_auth instead.
	for _, tc := range []struct {
		file *vsecrets.PolicyHookSecret
		name string
	}{
		{name: "no [policy_hook] table", file: nil},
		{name: "empty [policy_hook] table", file: &vsecrets.PolicyHookSecret{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := ResolveCredential(tc.file)
			require.NoError(t, err)
			assert.Nil(t, cred)
		})
	}
}

func TestResolveCredential_FromSecretsFile(t *testing.T) {
	cred, err := ResolveCredential(&vsecrets.PolicyHookSecret{APIKey: testAPIKey, SecretKey: testSecret})
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, testAPIKey, cred.APIKey)
	assert.Equal(t, testSecret, cred.Secret)
}

// The secrets file is the only source. This credential postdates the file, so unlike the
// aggregator and database credentials it never had an environment-variable contract to keep, and
// an operator has exactly one place to look.
func TestResolveCredential_IgnoresEnvironment(t *testing.T) {
	t.Setenv("VERIFIER_POLICY_HOOK_API_KEY", testAPIKey)
	t.Setenv("VERIFIER_POLICY_HOOK_SECRET_KEY", testSecret)

	cred, err := ResolveCredential(nil)
	require.NoError(t, err)
	assert.Nil(t, cred)
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
			assert.Contains(t, err.Error(), "secrets file", "the error must name which source the bad pair came from")
			assert.NotContains(t, err.Error(), testSecret, "an error an operator will log must never carry the secret")
			if tc.file.APIKey != "" {
				assert.NotContains(t, err.Error(), tc.file.APIKey, "nor the api key")
			}
		})
	}
}

// TestHTTPChecker_SignsRequest is the test the operator's side depends on: it recomputes the
// signature the way the published contract tells an endpoint to, and refuses the request if it
// does not match. A change to what the verifier signs fails here rather than in production
// against an endpoint that starts rejecting every call.
func TestHTTPChecker_SignsRequest(t *testing.T) {
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
		BaseURL:            srv.URL,
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

// The published contract tells an endpoint to recompute the signature over the request target it
// received, so what the verifier signs has to be the full path it POSTs, prefix included. An
// operator behind a gateway that routes on a path prefix is the case that would break silently:
// the base carries the prefix and the signature has to cover it.
func TestSignRequest_CoversFullEvaluatePath(t *testing.T) {
	body := []byte(`{"message_id":"0xabc"}`)
	now := time.UnixMilli(1780000000000)

	for _, tc := range []struct{ base, wantTarget string }{
		{base: "https://policy.example.com", wantTarget: "/v1/evaluate"},
		{base: "https://policy.example.com/", wantTarget: "/v1/evaluate"},
		{base: "https://acme.example/compliance", wantTarget: "/compliance/v1/evaluate"},
		{base: "https://acme.example/compliance/", wantTarget: "/compliance/v1/evaluate"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			endpoint, err := (&Config{BaseURL: tc.base}).EvaluateURL()
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, nil)
			require.NoError(t, err)
			require.Equal(t, tc.wantTarget, req.URL.RequestURI(),
				"the verifier must POST the base with the contract's operation path appended")
			require.NoError(t, hmac.SignHTTPRequest(req, testCredential(), body, now))

			want := hmac.GenerateStringToSign(
				http.MethodPost, tc.wantTarget, hmac.ComputeBodyHash(body), testAPIKey, "1780000000000")
			expected, err := hmac.ComputeHMAC(testSecret, want)
			require.NoError(t, err)

			assert.Equal(t, expected, req.Header.Get(hmac.HeaderSignature))
			assert.Equal(t, "1780000000000", req.Header.Get(hmac.HeaderTimestamp))
		})
	}
}
