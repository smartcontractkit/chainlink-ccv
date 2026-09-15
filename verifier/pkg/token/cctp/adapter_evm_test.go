package cctp

import (
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/internal"
)

func TestAdapterForResolvesEVM(t *testing.T) {
	adapter, err := AdapterFor(protocol.ChainSelector(chainsel.GETH_TESTNET.Selector))
	require.NoError(t, err)
	_, ok := adapter.(evmAdapter)
	require.True(t, ok, "an EVM selector must resolve to the EVM adapter")
}

func TestAdapterForUnregisteredFamily(t *testing.T) {
	// Selector 1 is in no chain-selectors family map, so no adapter can be resolved.
	_, err := AdapterFor(protocol.ChainSelector(1))
	require.Error(t, err)
}

func TestEVMAdapterEncodeTxHash(t *testing.T) {
	txHash := internal.MustByteSliceFromHex("0x912f22a13e9ccb979b621500f6952b2afd6e75be7eadaed93fc2625fe11c52a2")

	got, err := evmAdapter{}.EncodeTxHash(txHash)
	require.NoError(t, err)
	require.Equal(t, "0x912f22a13e9ccb979b621500f6952b2afd6e75be7eadaed93fc2625fe11c52a2", got)
}

func TestEVMAdapterDecodeAddress(t *testing.T) {
	decoded, err := evmAdapter{}.DecodeAddress("0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350")
	require.NoError(t, err)
	require.Equal(t, "0xca9142d0b9804ef5e239d3bc1c7aa0d1c74e7350", decoded.String())

	_, err = evmAdapter{}.DecodeAddress("0xzzzz")
	require.Error(t, err)
}
