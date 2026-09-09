package cctp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

const (
	solanaDevnet = protocol.ChainSelector(16423721717087811551)
	sepolia      = protocol.ChainSelector(16015286601757825753)

	// Real values from a Solana -> Sepolia burn, tx x76ZETWu...
	solanaTxHashHex = "2f85428658ad2f5d8f6ef86d948bbcafc17c0d5cdadb590a7129d7fdc7a9853d02a5476eb3d1d92eb7366b069973d2058810e18aabb62a93422045c92b3a850d"
	solanaTxHashB58 = "x76ZETWu5K5C4wmemgVqv72hE2FaawNb7EFKtjiD82ugNRvnpbcu12FEP4dzrNacfHTdQTsQuU8ukVLX2qrLxqi"
	// The pool signer PDA, as Circle returns it in messageSender for a Solana burn.
	solanaSenderB58 = "2v3hCkRJGSM4N29xwjA9TePBrC3uM8BnE3r7ns2W9BjR"
	solanaSenderHex = "0x1c7283d45b49957afb150fedd003d8d5cecd20915936bee9a9b9cf085e1bdfb4"
)

// Circle's API keys Solana transactions by their base58 signature; a hex-encoded signature
// returns 404, which the client reports as "token data not ready".
func TestEncodeTxHash(t *testing.T) {
	raw, err := protocol.NewByteSliceFromHex("0x" + solanaTxHashHex)
	require.NoError(t, err)

	got, err := encodeTxHash(solanaDevnet, raw)
	require.NoError(t, err)
	require.Equal(t, solanaTxHashB58, got)

	got, err = encodeTxHash(sepolia, raw)
	require.NoError(t, err)
	require.Equal(t, "0x"+solanaTxHashHex, got)
}

// Circle returns each address in the native encoding of its own chain, so a Solana messageSender
// is base58 and cannot be parsed as hex.
func TestDecodeAddress(t *testing.T) {
	fromB58, err := decodeAddress(solanaDevnet, solanaSenderB58)
	require.NoError(t, err)

	fromHex, err := protocol.NewUnknownAddressFromHex(solanaSenderHex)
	require.NoError(t, err)
	require.True(t, fromB58.Equal(fromHex), "base58 sender must decode to the configured verifier address")

	_, err = decodeAddress(sepolia, "0x32a0973b57E06b9dEc546B0C4C3DC07C4B5BC353")
	require.NoError(t, err)

	_, err = decodeAddress(solanaDevnet, "0xnot-base58")
	require.Error(t, err)
}
