package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		cfg         *Config
		name        string
		errContains string
	}{
		{
			name: "nil config is valid - the hook is optional",
			cfg:  nil,
		},
		{
			name: "https endpoint with defaults",
			cfg:  &Config{BaseURL: "https://policy.example.com"},
		},
		{
			name: "https endpoint with explicit durations",
			cfg: &Config{
				BaseURL:        "https://policy.example.com",
				RequestTimeout: "2s",
				RetryDelay:     "30s",
			},
		},
		{
			name:        "missing endpoint",
			cfg:         &Config{RequestTimeout: "2s"},
			errContains: "base_url is required",
		},
		{
			name:        "blank endpoint",
			cfg:         &Config{BaseURL: "   "},
			errContains: "base_url is required",
		},
		{
			name:        "endpoint with no host",
			cfg:         &Config{BaseURL: "https://"},
			errContains: "has no host",
		},
		{
			name:        "http endpoint without the insecure opt-in",
			cfg:         &Config{BaseURL: "http://policy.example.com"},
			errContains: "set insecure_connection",
		},
		{
			name: "http endpoint with the insecure opt-in",
			cfg: &Config{
				BaseURL:            "http://fake:9111/policy",
				InsecureConnection: true,
			},
		},
		{
			name:        "non-http scheme",
			cfg:         &Config{BaseURL: "grpc://policy.example.com"},
			errContains: "must use http or https",
		},
		{
			name: "base with a path prefix, for an endpoint behind a gateway",
			cfg:  &Config{BaseURL: "https://acme.example/compliance"},
		},
		{
			// The likeliest operator mistake: pasting the full endpoint rather than its base.
			// Silently accepting it would POST /v1/evaluate/v1/evaluate and 404 every message.
			name:        "base that already carries the operation path",
			cfg:         &Config{BaseURL: "https://policy.example.com/v1/evaluate"},
			errContains: "already ends in /v1/evaluate",
		},
		{
			name:        "base that already carries the operation path with a trailing slash",
			cfg:         &Config{BaseURL: "https://policy.example.com/v1/evaluate/"},
			errContains: "already ends in /v1/evaluate",
		},
		{
			// A query cannot survive having a path appended after it.
			name:        "base with a query string",
			cfg:         &Config{BaseURL: "https://policy.example.com?tenant=acme"},
			errContains: "query string",
		},
		{
			name:        "base with a fragment",
			cfg:         &Config{BaseURL: "https://policy.example.com#section"},
			errContains: "fragment",
		},
		{
			name:        "unparseable endpoint",
			cfg:         &Config{BaseURL: "https://policy.example.com/\x7f"},
			errContains: "not a valid URL",
		},
		{
			name: "malformed request timeout",
			cfg: &Config{
				BaseURL:        "https://policy.example.com",
				RequestTimeout: "5 seconds",
			},
			errContains: "request_timeout",
		},
		{
			name: "non-positive request timeout",
			cfg: &Config{
				BaseURL:        "https://policy.example.com",
				RequestTimeout: "0s",
			},
			errContains: "request_timeout must be positive",
		},
		{
			name: "request timeout at the maximum",
			cfg: &Config{
				BaseURL:        "https://policy.example.com",
				RequestTimeout: "15s",
			},
		},
		{
			// A batch of policy calls has to finish inside the task queue's job lock, or the
			// job is reclaimed and every message in it is evaluated a second time.
			name: "request timeout over the maximum",
			cfg: &Config{
				BaseURL:        "https://policy.example.com",
				RequestTimeout: "30s",
			},
			errContains: "exceeds the 15s maximum",
		},
		{
			name: "malformed retry delay",
			cfg: &Config{
				BaseURL:    "https://policy.example.com",
				RetryDelay: "soon",
			},
			errContains: "retry_delay",
		},
		{
			name: "negative retry delay",
			cfg: &Config{
				BaseURL:    "https://policy.example.com",
				RetryDelay: "-1s",
			},
			errContains: "retry_delay must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.errContains == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestConfig_Durations(t *testing.T) {
	t.Run("empty falls back to the defaults", func(t *testing.T) {
		cfg := &Config{BaseURL: "https://policy.example.com"}

		timeout, err := cfg.RequestTimeoutDuration()
		require.NoError(t, err)
		assert.Equal(t, DefaultRequestTimeout, timeout)

		delay, err := cfg.RetryDelayDuration()
		require.NoError(t, err)
		assert.Equal(t, DefaultRetryDelay, delay)
	})

	t.Run("explicit values win", func(t *testing.T) {
		cfg := &Config{
			BaseURL:        "https://policy.example.com",
			RequestTimeout: "1500ms",
			RetryDelay:     "45s",
		}

		timeout, err := cfg.RequestTimeoutDuration()
		require.NoError(t, err)
		assert.Equal(t, 1500*time.Millisecond, timeout)

		delay, err := cfg.RetryDelayDuration()
		require.NoError(t, err)
		assert.Equal(t, 45*time.Second, delay)
	})
}

// EvaluateURL is what the verifier actually POSTs, so the contract's operation path has to end up
// on it exactly once, whatever shape the operator wrote the base in.
func TestConfig_EvaluateURL(t *testing.T) {
	for _, tc := range []struct{ base, want string }{
		{base: "https://policy.example.com", want: "https://policy.example.com/v1/evaluate"},
		{base: "https://policy.example.com/", want: "https://policy.example.com/v1/evaluate"},
		{base: "  https://policy.example.com  ", want: "https://policy.example.com/v1/evaluate"},
		{base: "https://acme.example/compliance", want: "https://acme.example/compliance/v1/evaluate"},
		{base: "https://acme.example/compliance/", want: "https://acme.example/compliance/v1/evaluate"},
		{base: "http://fake:9111/policy", want: "http://fake:9111/policy/v1/evaluate"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			got, err := (&Config{BaseURL: tc.base}).EvaluateURL()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := (&Config{}).EvaluateURL()
	require.Error(t, err, "a missing base has no URL to derive")
}
