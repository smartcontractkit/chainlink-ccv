package policy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// newTestChecker points a checker at srv. The endpoint is plain http, which is what
// insecure_connection exists for.
func newTestChecker(t *testing.T, srv *httptest.Server, timeout string) *HTTPChecker {
	t.Helper()

	checker, err := NewHTTPChecker(logger.Test(t), &Config{
		EndpointURL:        srv.URL + "/v1/evaluate",
		RequestTimeout:     timeout,
		InsecureConnection: true,
	})
	require.NoError(t, err)
	return checker
}

func testRequest() EvaluateRequest {
	return EvaluateRequest{
		SchemaVersion: SchemaVersion,
		VerifierID:    "committee-verifier-1",
		MessageID:     "0xabc",
		Message:       MessageV1{SourceChainSelector: 1, DestChainSelector: 2},
	}
}

func TestHTTPChecker_Evaluate_Pass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision":"PASS"}`)
	}))
	defer srv.Close()

	verdict, err := newTestChecker(t, srv, "").Evaluate(t.Context(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, DecisionPass, verdict.Decision)
	assert.Empty(t, verdict.Reason)
}

func TestHTTPChecker_Evaluate_Fail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"FAIL","reason":"sanctioned sender"}`)
	}))
	defer srv.Close()

	verdict, err := newTestChecker(t, srv, "").Evaluate(t.Context(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, DecisionFail, verdict.Decision)
	assert.Equal(t, "sanctioned sender", verdict.Reason)
}

// TestHTTPChecker_Evaluate_MessageIDEcho covers the optional message_id echo. Nothing else in a
// response ties a verdict to the message it answers, so an endpoint that echoes the ID lets the
// verifier refuse a verdict that reached it for a different message - a cache, a proxy, or a load
// balancer in front of the endpoint that crossed two requests. Signing on a crossed PASS would
// attest a message the policy never saw.
func TestHTTPChecker_Evaluate_MessageIDEcho(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		errContains string
		want        Decision
	}{
		{
			name: "matching echo is accepted",
			body: `{"decision":"PASS","message_id":"0xabc"}`,
			want: DecisionPass,
		},
		{
			// Endpoints differ on hex casing and the contract does not pin it, so only a
			// genuinely different ID is a mismatch.
			name: "echo differing only in hex case is accepted",
			body: `{"decision":"PASS","message_id":"0xABC"}`,
			want: DecisionPass,
		},
		{
			name: "absent echo skips the check",
			body: `{"decision":"PASS"}`,
			want: DecisionPass,
		},
		{
			name:        "echo for a different message is refused",
			body:        `{"decision":"PASS","message_id":"0xdef"}`,
			errContains: "verdict is for a different message",
		},
		{
			// A crossed FAIL is refused for the same reason a crossed PASS is: it would drop
			// a message on a verdict that was never about it.
			name:        "crossed rejection is refused rather than dropped",
			body:        `{"decision":"FAIL","message_id":"0xdef","reason":"sanctioned sender"}`,
			errContains: "verdict is for a different message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			verdict, err := newTestChecker(t, srv, "").Evaluate(t.Context(), testRequest())
			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, verdict.Decision)
		})
	}
}

// The request shape is a published contract, so assert what actually goes on the wire.
func TestHTTPChecker_Evaluate_RequestShape(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotAccept      string
		gotPath        string
		gotBody        EvaluateRequest
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotPath = r.URL.Path
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		_, _ = io.WriteString(w, `{"decision":"PASS"}`)
	}))
	defer srv.Close()

	req := testRequest()
	_, err := newTestChecker(t, srv, "").Evaluate(t.Context(), req)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "application/json", gotContentType)
	assert.Equal(t, "application/json", gotAccept)
	assert.Equal(t, "/v1/evaluate", gotPath, "the endpoint URL is used verbatim, with nothing appended")
	assert.Equal(t, req, gotBody)
}

func TestHTTPChecker_Evaluate_UnusableResponses(t *testing.T) {
	tests := []struct {
		handler     http.HandlerFunc
		name        string
		errContains string
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			errContains: "status 500",
		},
		{
			name: "client error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			errContains: "status 401",
		},
		{
			name: "not found",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			errContains: "status 404",
		},
		{
			name: "rate limited",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
			errContains: "status 429",
		},
		{
			name: "redirect is not followed",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "http://elsewhere.example.com/v1/evaluate")
				w.WriteHeader(http.StatusFound)
			},
			errContains: "status 302",
		},
		{
			name: "body is not JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `not json at all`)
			},
			errContains: "failed to decode policy response",
		},
		{
			name: "decision is missing",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"reason":"nothing to see here"}`)
			},
			errContains: "unrecognized decision",
		},
		{
			name: "decision is not a v1 verdict",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"decision":"MAYBE"}`)
			},
			errContains: "unrecognized decision",
		},
		{
			name: "body is too large",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"decision":"PASS","reason":"`)
				_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBytes+1))
				_, _ = io.WriteString(w, `"}`)
			},
			errContains: "exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			verdict, err := newTestChecker(t, srv, "").Evaluate(t.Context(), testRequest())
			require.Error(t, err, "an unusable response must be an error, never a FAIL")
			assert.Contains(t, err.Error(), tt.errContains)
			assert.Empty(t, verdict.Decision)
		})
	}
}

func TestHTTPChecker_Evaluate_Timeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = io.WriteString(w, `{"decision":"PASS"}`)
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	_, err := newTestChecker(t, srv, "50ms").Evaluate(t.Context(), testRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}

func TestHTTPChecker_Evaluate_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // Nothing is listening on that port any more.

	checker, err := NewHTTPChecker(logger.Test(t), &Config{EndpointURL: url, InsecureConnection: true})
	require.NoError(t, err)

	_, err = checker.Evaluate(t.Context(), testRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unreachable")
}

func TestHTTPChecker_Evaluate_CallerDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	// A caller-side deadline must surface as an error too, not as a verdict.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	_, err := newTestChecker(t, srv, "10s").Evaluate(ctx, testRequest())
	require.Error(t, err)
}

func TestNewHTTPChecker_RejectsBadConfig(t *testing.T) {
	_, err := NewHTTPChecker(logger.Test(t), nil)
	require.Error(t, err)

	_, err = NewHTTPChecker(logger.Test(t), &Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint_url is required")

	_, err = NewHTTPChecker(logger.Test(t), &Config{EndpointURL: "http://policy.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insecure_connection")
}
