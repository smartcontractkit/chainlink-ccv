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
			cfg:  &Config{EndpointURL: "https://policy.example.com/v1/evaluate"},
		},
		{
			name: "https endpoint with explicit durations",
			cfg: &Config{
				EndpointURL:    "https://policy.example.com/v1/evaluate",
				RequestTimeout: "2s",
				RetryDelay:     "30s",
			},
		},
		{
			name:        "missing endpoint",
			cfg:         &Config{RequestTimeout: "2s"},
			errContains: "endpoint_url is required",
		},
		{
			name:        "blank endpoint",
			cfg:         &Config{EndpointURL: "   "},
			errContains: "endpoint_url is required",
		},
		{
			name:        "endpoint with no host",
			cfg:         &Config{EndpointURL: "https:///v1/evaluate"},
			errContains: "has no host",
		},
		{
			name:        "http endpoint without the insecure opt-in",
			cfg:         &Config{EndpointURL: "http://policy.example.com/v1/evaluate"},
			errContains: "set insecure_connection",
		},
		{
			name: "http endpoint with the insecure opt-in",
			cfg: &Config{
				EndpointURL:        "http://fake:9111/policy/v1/evaluate",
				InsecureConnection: true,
			},
		},
		{
			name:        "non-http scheme",
			cfg:         &Config{EndpointURL: "grpc://policy.example.com"},
			errContains: "must use http or https",
		},
		{
			name:        "unparseable endpoint",
			cfg:         &Config{EndpointURL: "https://policy.example.com/\x7f"},
			errContains: "not a valid URL",
		},
		{
			name: "malformed request timeout",
			cfg: &Config{
				EndpointURL:    "https://policy.example.com",
				RequestTimeout: "5 seconds",
			},
			errContains: "request_timeout",
		},
		{
			name: "non-positive request timeout",
			cfg: &Config{
				EndpointURL:    "https://policy.example.com",
				RequestTimeout: "0s",
			},
			errContains: "request_timeout must be positive",
		},
		{
			name: "request timeout at the maximum",
			cfg: &Config{
				EndpointURL:    "https://policy.example.com",
				RequestTimeout: "15s",
			},
		},
		{
			// A batch of policy calls has to finish inside the task queue's job lock, or the
			// job is reclaimed and every message in it is evaluated a second time.
			name: "request timeout over the maximum",
			cfg: &Config{
				EndpointURL:    "https://policy.example.com",
				RequestTimeout: "30s",
			},
			errContains: "exceeds the 15s maximum",
		},
		{
			name: "malformed retry delay",
			cfg: &Config{
				EndpointURL: "https://policy.example.com",
				RetryDelay:  "soon",
			},
			errContains: "retry_delay",
		},
		{
			name: "negative retry delay",
			cfg: &Config{
				EndpointURL: "https://policy.example.com",
				RetryDelay:  "-1s",
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
		cfg := &Config{EndpointURL: "https://policy.example.com"}

		timeout, err := cfg.RequestTimeoutDuration()
		require.NoError(t, err)
		assert.Equal(t, DefaultRequestTimeout, timeout)

		delay, err := cfg.RetryDelayDuration()
		require.NoError(t, err)
		assert.Equal(t, DefaultRetryDelay, delay)
	})

	t.Run("explicit values win", func(t *testing.T) {
		cfg := &Config{
			EndpointURL:    "https://policy.example.com",
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
