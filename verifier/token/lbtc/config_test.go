package lbtc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func Test_TryParsing(t *testing.T) {
	testAddr1Hex := "0x1111111111111111111111111111111111111111"
	testAddr2Hex := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAddr1, err := protocol.NewUnknownAddressFromHex(testAddr1Hex)
	require.NoError(t, err)
	testAddr2, err := protocol.NewUnknownAddressFromHex(testAddr2Hex)
	require.NoError(t, err)

	tests := []struct {
		name    string
		t       string
		v       string
		data    map[string]any
		want    *LBTCConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with all fields",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api":            "https://lbtc-api.example.com",
				"attestation_api_timeout":    "5s",
				"attestation_api_interval":   "200ms",
				"attestation_api_batch_size": 50,
				"addresses": map[string]any{
					"1": testAddr1Hex,
					"2": testAddr2Hex,
				},
			},
			want: &LBTCConfig{
				AttestationAPI:          "https://lbtc-api.example.com",
				AttestationAPITimeout:   5 * time.Second,
				AttestationAPIInterval:  200 * time.Millisecond,
				AttestationAPIBatchSize: 50,
				ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: testAddr1,
					2: testAddr2,
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with default values",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api": "https://lbtc-api.example.com",
				"addresses": map[string]any{
					"1": testAddr1Hex,
				},
			},
			want: &LBTCConfig{
				AttestationAPI:          "https://lbtc-api.example.com",
				AttestationAPITimeout:   1 * time.Second,
				AttestationAPIInterval:  100 * time.Millisecond,
				AttestationAPIBatchSize: 20,
				ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: testAddr1,
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with batch size as string",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api":            "https://lbtc-api.example.com",
				"attestation_api_batch_size": "30",
				"addresses": map[string]any{
					"1": testAddr1Hex,
				},
			},
			want: &LBTCConfig{
				AttestationAPI:          "https://lbtc-api.example.com",
				AttestationAPITimeout:   1 * time.Second,
				AttestationAPIInterval:  100 * time.Millisecond,
				AttestationAPIBatchSize: 30,
				ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: testAddr1,
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported type",
			t:    "invalid",
			v:    "1.0",
			data: map[string]any{
				"attestation_api": "https://lbtc-api.example.com",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported verifier type",
		},
		{
			name: "unsupported version",
			t:    "lbtc",
			v:    "2.0",
			data: map[string]any{
				"attestation_api": "https://lbtc-api.example.com",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported verifier type",
		},
		{
			name: "missing attestation_api",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"addresses": map[string]any{
					"1": testAddr1Hex,
				},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "attestation_api field is required",
		},
		{
			name: "invalid attestation_api_timeout",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api":         "https://lbtc-api.example.com",
				"attestation_api_timeout": "not-a-duration",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid attestation_api_timeout",
		},
		{
			name: "invalid attestation_api_interval",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api":          "https://lbtc-api.example.com",
				"attestation_api_interval": "invalid",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid attestation_api_interval",
		},
		{
			name: "invalid attestation_api_batch_size",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api":            "https://lbtc-api.example.com",
				"attestation_api_batch_size": "invalid",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid attestation_api_batch_size",
		},
		{
			name: "invalid addresses",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api": "https://lbtc-api.example.com",
				"addresses":       "not-a-map",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid addresses",
		},
		{
			name: "empty addresses map",
			t:    "lbtc",
			v:    "1.0",
			data: map[string]any{
				"attestation_api": "https://lbtc-api.example.com",
				"addresses":       map[string]any{},
			},
			want: &LBTCConfig{
				AttestationAPI:          "https://lbtc-api.example.com",
				AttestationAPITimeout:   1 * time.Second,
				AttestationAPIInterval:  100 * time.Millisecond,
				AttestationAPIBatchSize: 20,
				ParsedVerifiers:         map[protocol.ChainSelector]protocol.UnknownAddress{},
			},
			wantErr: false,
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
				assert.Equal(t, tt.want.AttestationAPIBatchSize, got.AttestationAPIBatchSize)
				assert.Equal(t, tt.want.ParsedVerifiers, got.ParsedVerifiers)
			}
		})
	}
}
