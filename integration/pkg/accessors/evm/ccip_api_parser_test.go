package evm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestAccessorReturnsItselfAsTheCCIPAPIParser(t *testing.T) {
	t.Parallel()

	a := &accessor{}
	parser, err := a.CCIPAPIParser()
	require.NoError(t, err)
	require.Same(t, a, parser)

	const hex = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	got, err := parser.DecodeAddress(hex)
	require.NoError(t, err)
	want, err := protocol.NewUnknownAddressFromHex(hex)
	require.NoError(t, err)
	require.Equal(t, want, got)

	_, err = parser.DecodeAddress("0xzz")
	require.Error(t, err)
}
