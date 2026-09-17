package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestEVMCodecDomain(t *testing.T) {
	a := &accessor{}
	domain, ok := a.Domain(protocol.ChainSelector(sel.GETH_TESTNET.Selector))
	require.True(t, ok)
	assert.Equal(t, uint32(100), domain)

	// The EVM catalog holds no Solana selector.
	_, ok = a.Domain(protocol.ChainSelector(sel.SOLANA_DEVNET.Selector))
	assert.False(t, ok)
}

func TestEVMCodecEncodeTxHash(t *testing.T) {
	a := &accessor{}
	const hex = "0x912f22a13e9ccb979b621500f6952b2afd6e75be7eadaed93fc2625fe11c52a2"
	txHash, err := protocol.NewByteSliceFromHex(hex)
	require.NoError(t, err)
	assert.Equal(t, hex, a.EncodeTxHash(txHash))
}

func TestEVMCodecDecodeAddress(t *testing.T) {
	a := &accessor{}
	const hex = "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350"
	addr, err := a.DecodeAddress(hex)
	require.NoError(t, err)
	expected, err := protocol.NewUnknownAddressFromHex(hex)
	require.NoError(t, err)
	assert.Equal(t, expected, addr)

	_, err = a.DecodeAddress("0xzzzz")
	require.Error(t, err)
}
