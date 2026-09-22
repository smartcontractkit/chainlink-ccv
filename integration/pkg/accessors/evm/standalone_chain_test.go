package evm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRawNodeURLs(t *testing.T) {
	t.Parallel()

	require.Empty(t, rawNodeURLs(nil))
	require.Empty(t, rawNodeURLs([]Node{{}}))
	require.Equal(t,
		[]map[string]string{
			{nodeURLKeyHTTP: "http://rpc-1.example.com", nodeURLKeyWS: "wss://rpc-1.example.com"},
			{nodeURLKeyHTTP: "http://rpc-2.example.com"},
		},
		rawNodeURLs([]Node{
			{Name: "primary", HTTPUrl: " http://rpc-1.example.com ", WSUrl: "wss://rpc-1.example.com"},
			{Name: "backup", HTTPUrl: "http://rpc-2.example.com"},
			{Name: "empty"},
		}),
	)
}
