package evm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestCCIPApiParserDecodeAddress(t *testing.T) {
	t.Parallel()

	const lower = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	want := common.HexToAddress(lower).Bytes()

	tests := []struct {
		name    string
		address string
		wantErr string
	}{
		{name: "lowercase with prefix", address: lower},
		{name: "checksummed", address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
		{name: "without prefix", address: lower[2:]},
		{name: "empty", address: "", wantErr: "got 0 bytes"},
		{name: "not hex", address: "0xzz", wantErr: "invalid EVM address"},
		{name: "too short", address: "0x1234", wantErr: "got 2 bytes"},
		{name: "32 byte padded", address: "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", wantErr: "got 32 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewCCIPApiParser().DecodeAddress(tt.address)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, want, []byte(got))
		})
	}
}

func TestAccessorReturnsTheEVMCCIPApiParser(t *testing.T) {
	t.Parallel()

	parser, err := (&accessor{}).CCIPApiParser()
	require.NoError(t, err)
	got, err := parser.DecodeAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	require.NoError(t, err)
	require.Len(t, got, common.AddressLength)
}
