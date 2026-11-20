package evmconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConversionBroadcastEndpointSummary(t *testing.T) {
	conversion, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '11155111'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://primary.example.com'
HTTPURLExtraWrite = 'https://primary-write.example.com'
[[EVM.Nodes]]
Name = 'broadcast'
HTTPURL = 'https://broadcast.example.com'
HTTPURLExtraWrite = 'https://broadcast-write.example.com'
SendOnly = true
`))
	require.NoError(t, err)
	require.Len(t, conversion.BroadcastEndpoints, 1)
	summary := conversion.BroadcastEndpoints[0]
	require.Equal(t, BroadcastEndpointSummary{
		ChainID:                    "11155111",
		LegacyEndpoints:            4,
		StandaloneEndpoints:        1,
		SendOnlyEndpointsDropped:   2,
		ExtraWriteEndpointsDropped: 2,
		ReviewRequired:             true,
	}, summary)

	encoded, err := json.Marshal(summary)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "example.com")
}

func TestConversionBroadcastEndpointSummaryWithoutLoss(t *testing.T) {
	conversion, err := convertChainlinkNodeConfig([]byte(`
[[EVM]]
ChainID = '11155111'
[[EVM.Nodes]]
Name = 'primary'
HTTPURL = 'https://primary.example.com'
[[EVM.Nodes]]
Name = 'backup'
HTTPURL = 'https://backup.example.com'
`))
	require.NoError(t, err)
	require.Len(t, conversion.BroadcastEndpoints, 1)
	require.Equal(t, 2, conversion.BroadcastEndpoints[0].LegacyEndpoints)
	require.Equal(t, 2, conversion.BroadcastEndpoints[0].StandaloneEndpoints)
	require.False(t, conversion.BroadcastEndpoints[0].ReviewRequired)
}
