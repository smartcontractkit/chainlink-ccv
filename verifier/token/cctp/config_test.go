package cctp

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

	testResolverAddr1Hex := "0x3333333333333333333333333333333333333333"
	testResolverAddr2Hex := "0x4444444444444444444444444444444444444444"
	testResolverAddr1, err := protocol.NewUnknownAddressFromHex(testResolverAddr1Hex)
	require.NoError(t, err)
	testResolverAddr2, err := protocol.NewUnknownAddressFromHex(testResolverAddr2Hex)
	require.NoError(t, err)

	tests := []struct {
		name    string
		t       string
		v       string
		data    map[string]any
		want    *CCTPConfig
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
				"verifier_version":         "12345678",
				"verifier_resolver_addresses": map[string]any{
					"1": testAddr1Hex,
					"2": testAddr2Hex,
				},
				"verifier_addresses": map[string]any{
					"1": testResolverAddr1Hex,
					"2": testResolverAddr2Hex,
				},
			},
			want: &CCTPConfig{
				AttestationAPI:         "https://iris-api.circle.com",
				AttestationAPITimeout:  5 * time.Second,
				AttestationAPIInterval: 200 * time.Millisecond,
				AttestationAPICooldown: 10 * time.Minute,
				VerifierVersion:        "12345678",
				ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: testAddr1,
					2: testAddr2,
				},
				ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: testResolverAddr1,
					2: testResolverAddr2,
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
				"verifier_resolver_addresses": map[string]any{
					"1": testAddr1Hex,
				},
			},
			want: &CCTPConfig{
				AttestationAPI:         "https://iris-api.circle.com",
				AttestationAPITimeout:  1 * time.Second,
				AttestationAPIInterval: 100 * time.Millisecond,
				AttestationAPICooldown: 5 * time.Minute,
				VerifierVersion:        DefaultVerifierVersionHex,
				ParsedVerifierResolvers: map[protocol.ChainSelector]protocol.UnknownAddress{
					1: testAddr1,
				},
				ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{},
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
					"1": testAddr1Hex,
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
			name: "invalid verifier_resolver_addresses",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api":             "https://iris-api.circle.com",
				"verifier_resolver_addresses": "not-a-map",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid verifier_resolver_addresses",
		},
		{
			name: "invalid verifier_addresses",
			t:    "cctp",
			v:    "2.0",
			data: map[string]any{
				"attestation_api":    "https://iris-api.circle.com",
				"verifier_addresses": "not-a-map",
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid verifier_addresses",
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
				assert.Equal(t, tt.want.VerifierVersion, got.VerifierVersion)
				assert.Equal(t, tt.want.ParsedVerifierResolvers, got.ParsedVerifierResolvers)
				assert.Equal(t, tt.want.ParsedVerifiers, got.ParsedVerifiers)
			}
		})
	}
}

func TestCCTPConfig_ParsedVerifierVersion(t *testing.T) {
	tests := []struct {
		name    string
		config  CCTPConfig
		want    protocol.ByteSlice
		wantErr bool
	}{
		{
			name: "valid hex string with default value",
			config: CCTPConfig{
				VerifierVersion: DefaultVerifierVersionHex,
			},
			want:    protocol.ByteSlice{0x8e, 0x1d, 0x1a, 0x9d},
			wantErr: false,
		},
		{
			name: "valid hex string without leading zeros",
			config: CCTPConfig{
				VerifierVersion: "0x12345678",
			},
			want:    protocol.ByteSlice{0x12, 0x34, 0x56, 0x78},
			wantErr: false,
		},
		{
			name: "invalid hex string",
			config: CCTPConfig{
				VerifierVersion: "not-hex",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty hex string",
			config: CCTPConfig{
				VerifierVersion: "",
			},
			want:    protocol.ByteSlice{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.ParsedVerifierVersion()

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
