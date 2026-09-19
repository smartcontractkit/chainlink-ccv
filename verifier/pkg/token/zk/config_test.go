package zk

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
	lightClientHex := "0xf66AB2b4C1B7045ea51e4d905F91c40EAB31304E"
	testAddr1, err := protocol.NewUnknownAddressFromHex(testAddr1Hex)
	require.NoError(t, err)
	testAddr2, err := protocol.NewUnknownAddressFromHex(testAddr2Hex)
	require.NoError(t, err)
	lightClient, err := protocol.NewUnknownAddressFromHex(lightClientHex)
	require.NoError(t, err)

	resolvers := map[string]any{
		"16015286601757825753": testAddr1Hex,
		"3478487238524512106":  testAddr2Hex,
	}
	lane := map[string]any{
		"source_chain_selector": "16015286601757825753",
		"dest_chain_selector":   "3478487238524512106",
		"light_client":          lightClientHex,
	}
	parsedResolvers := map[protocol.ChainSelector]protocol.UnknownAddress{
		16015286601757825753: testAddr1,
		3478487238524512106:  testAddr2,
	}
	parsedLanes := []Lane{{SourceChainSelector: 16015286601757825753, DestChainSelector: 3478487238524512106, LightClient: lightClient}}

	tests := []struct {
		name    string
		t       string
		v       string
		data    map[string]any
		want    *ZKConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with all fields",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"not_proven_retry":            "90s",
				"verifier_version":            "0xabcdef12",
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane},
			},
			want: &ZKConfig{
				NotProvenRetry:          90 * time.Second,
				VerifierVersion:         protocol.ByteSlice{0xab, 0xcd, 0xef, 0x12},
				ParsedVerifierResolvers: parsedResolvers,
				ParsedLanes:             parsedLanes,
			},
			wantErr: false,
		},
		{
			name: "valid config with default values",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane},
			},
			want: &ZKConfig{
				NotProvenRetry:          60 * time.Second,
				VerifierVersion:         DefaultVerifierVersion,
				ParsedVerifierResolvers: parsedResolvers,
				ParsedLanes:             parsedLanes,
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			t:    "cctp",
			v:    "1.0",
			data: map[string]any{
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported verifier type",
		},
		{
			name: "wrong version",
			t:    "zk",
			v:    "2.0",
			data: map[string]any{
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported verifier type",
		},
		{
			name: "invalid not_proven_retry",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"not_proven_retry":            "invalid",
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid not_proven_retry",
		},
		{
			name: "invalid verifier_version",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_version":            "not-hex",
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "invalid verifier_version",
		},
		{
			name: "verifier_version of wrong length",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_version":            "0xabcd",
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "verifier_version must be 4 bytes, got 2",
		},
		{
			name: "missing lanes",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_resolver_addresses": resolvers,
			},
			want:    nil,
			wantErr: true,
			errMsg:  "at least one lane is required",
		},
		{
			name: "chain selector not a string",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_resolver_addresses": resolvers,
				"lanes": []map[string]any{{
					"source_chain_selector": int64(1),
					"dest_chain_selector":   "3478487238524512106",
					"light_client":          lightClientHex,
				}},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "expected a chain selector string",
		},
		{
			name: "missing light_client",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_resolver_addresses": resolvers,
				"lanes": []map[string]any{{
					"source_chain_selector": "16015286601757825753",
					"dest_chain_selector":   "3478487238524512106",
				}},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "light_client field is required",
		},
		{
			name: "duplicate lane",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_resolver_addresses": resolvers,
				"lanes":                       []map[string]any{lane, lane},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "duplicate lane",
		},
		{
			name: "lane chain without resolver",
			t:    "zk",
			v:    "1.0",
			data: map[string]any{
				"verifier_resolver_addresses": map[string]any{"16015286601757825753": testAddr1Hex},
				"lanes":                       []map[string]any{lane},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "verifier_resolver_addresses has no entry for lane chain 3478487238524512106",
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
				assert.Equal(t, tt.want.NotProvenRetry, got.NotProvenRetry)
				assert.Equal(t, tt.want.VerifierVersion, got.VerifierVersion)
				assert.Equal(t, tt.want.ParsedVerifierResolvers, got.ParsedVerifierResolvers)
				assert.Equal(t, tt.want.ParsedLanes, got.ParsedLanes)
			}
		})
	}
}
