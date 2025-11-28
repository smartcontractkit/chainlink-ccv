package cctp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func Test_TryParsing(t *testing.T) {
	tests := []struct {
		name    string
		t       string
		v       string
		data    map[string]any
		want    *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with all fields",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api":          "https://iris-api.circle.com",
				"attestation_api_timeout":  "5s",
				"attestation_api_interval": "200ms",
				"attestation_api_cooldown": "10m",
				"addresses": map[string]any{
					"1": "0xVerifier1",
					"2": "0xVerifier2",
				},
			},
			want: &Config{
				AttestationAPI:         "https://iris-api.circle.com",
				AttestationAPITimeout:  5 * time.Second,
				AttestationAPIInterval: 200 * time.Millisecond,
				AttestationAPICooldown: 10 * time.Minute,
				Verifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: protocol.UnknownAddress("0xVerifier1"),
					2: protocol.UnknownAddress("0xVerifier2"),
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with default values",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api": "https://iris-api.circle.com",
				"addresses": map[string]any{
					"1": "0xVerifier1",
				},
			},
			want: &Config{
				AttestationAPI:         "https://iris-api.circle.com",
				AttestationAPITimeout:  1 * time.Second,
				AttestationAPIInterval: 100 * time.Millisecond,
				AttestationAPICooldown: 5 * time.Minute,
				Verifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: protocol.UnknownAddress("0xVerifier1"),
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported type",
			t:    "invalid",
			v:    "2.0",
			data: map[string]any{
				"attestation_api": "https://iris-api.circle.com",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported verifier type",
		},
		{
			name: "unsupported version",
			t:    "cctp",
			v:    "1.0",
			data: map[string]any{
				"attestation_api": "https://iris-api.circle.com",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported verifier type",
		},
		{
			name: "missing attestation_api",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"addresses": map[string]any{
					"1": "0xVerifier1",
				},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "attestation_api field is required",
		},
		{
			name: "invalid attestation_api_timeout",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api":         "https://iris-api.circle.com",
				"attestation_api_timeout": "not-a-duration",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid attestation_api_timeout",
		},
		{
			name: "invalid attestation_api_interval",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api":          "https://iris-api.circle.com",
				"attestation_api_interval": "invalid",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid attestation_api_interval",
		},
		{
			name: "invalid attestation_api_cooldown",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api":          "https://iris-api.circle.com",
				"attestation_api_cooldown": "invalid",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid attestation_api_cooldown",
		},
		{
			name: "invalid addresses",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api": "https://iris-api.circle.com",
				"addresses":       "not-a-map",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid addresses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TryParsing(tt.t, tt.v, tt.data)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, tt.want.AttestationAPI, got.AttestationAPI)
				assert.Equal(t, tt.want.AttestationAPITimeout, got.AttestationAPITimeout)
				assert.Equal(t, tt.want.AttestationAPIInterval, got.AttestationAPIInterval)
				assert.Equal(t, tt.want.AttestationAPICooldown, got.AttestationAPICooldown)
				assert.Equal(t, tt.want.Verifiers, got.Verifiers)
			}
		})
	}
}
