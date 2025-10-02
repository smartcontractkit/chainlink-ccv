package protocol

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestSignV27(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hash := Keccak256([]byte("test message"))

	// Sign with V27 compatibility
	r, s, addr, err := SignV27(hash[:], privateKey)
	require.NoError(t, err)

	// Verify the returned address matches the expected one
	expectedAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	require.Equal(t, expectedAddress, addr)

	// Verify the signature works with v=0 (which corresponds to v=27 onchain)
	sig := make([]byte, 65)
	copy(sig[0:32], r[:])
	copy(sig[32:64], s[:])
	sig[64] = 0 // SigToPub expects 0/1, not 27/28

	pubKey, err := crypto.SigToPub(hash[:], sig)
	require.NoError(t, err)

	// Verify it's the correct signer
	actualAddress := crypto.PubkeyToAddress(*pubKey)
	require.Equal(t, expectedAddress, actualAddress)
}

func TestSortSignaturesBySigner(t *testing.T) {
	// Create test signatures with different signer addresses
	signatures := []Data{
		{
			R:      [32]byte{0x03},
			S:      [32]byte{0x04},
			Signer: common.HexToAddress("0x0000000000000000000000000000000000000003"),
		},
		{
			R:      [32]byte{0x01},
			S:      [32]byte{0x02},
			Signer: common.HexToAddress("0x0000000000000000000000000000000000000001"),
		},
		{
			R:      [32]byte{0x05},
			S:      [32]byte{0x06},
			Signer: common.HexToAddress("0x0000000000000000000000000000000000000002"),
		},
	}

	// Sort signatures
	SortSignaturesBySigner(signatures)

	// Verify they are sorted by signer address
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000000001"), signatures[0].Signer)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000000002"), signatures[1].Signer)
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000000003"), signatures[2].Signer)

	// Verify the corresponding r,s values moved with their signers
	require.Equal(t, [32]byte{0x01}, signatures[0].R)
	require.Equal(t, [32]byte{0x02}, signatures[0].S)
	require.Equal(t, [32]byte{0x05}, signatures[1].R)
	require.Equal(t, [32]byte{0x06}, signatures[1].S)
	require.Equal(t, [32]byte{0x03}, signatures[2].R)
	require.Equal(t, [32]byte{0x04}, signatures[2].S)
}

func TestRecoverSigners(t *testing.T) {
	// Create multiple test private keys
	privateKeys := make([]*ecdsa.PrivateKey, 3)
	expectedAddresses := make([]common.Address, 3)
	for i := 0; i < 3; i++ {
		pk, err := crypto.GenerateKey()
		require.NoError(t, err)
		privateKeys[i] = pk
		expectedAddresses[i] = crypto.PubkeyToAddress(pk.PublicKey)
	}

	// Create a test hash
	hash := Keccak256([]byte("test message"))
	var hashArray [32]byte
	copy(hashArray[:], hash[:])

	// Sign with each private key using V27 compatibility
	rs := make([][32]byte, 0)
	ss := make([][32]byte, 0)
	for _, pk := range privateKeys {
		r, s, _, err := SignV27(hashArray[:], pk)
		require.NoError(t, err)
		rs = append(rs, r)
		ss = append(ss, s)
	}

	// Recover signers
	recoveredAddresses, err := RecoverSigners(hashArray, rs, ss)
	require.NoError(t, err)
	require.Len(t, recoveredAddresses, 3)

	// Verify all addresses match
	for i, expected := range expectedAddresses {
		require.Equal(t, expected, recoveredAddresses[i])
	}
}
