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
	recoveredAddresses, err := RecoverEcdsaSigners(hashArray, rs, ss)
	require.NoError(t, err)
	require.Len(t, recoveredAddresses, 3)

	// Verify all addresses match
	for i, expected := range expectedAddresses {
		require.Equal(t, expected, recoveredAddresses[i])
	}
}

func TestEncodeSingleSignature(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		sig := Data{
			R:      [32]byte{0x01},
			S:      [32]byte{0x02},
			Signer: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		}

		encoded, err := EncodeSingleEcdsaSignature(sig)
		require.NoError(t, err)
		require.Len(t, encoded, SingleEcdsaSignatureSize)
		require.Equal(t, sig.R[:], encoded[0:32])
		require.Equal(t, sig.S[:], encoded[32:64])
		require.Equal(t, sig.Signer[:], encoded[64:84])
	})

	t.Run("zero R", func(t *testing.T) {
		sig := Data{
			R:      [32]byte{},
			S:      [32]byte{0x02},
			Signer: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		}

		_, err := EncodeSingleEcdsaSignature(sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
	})

	t.Run("zero S", func(t *testing.T) {
		sig := Data{
			R:      [32]byte{0x01},
			S:      [32]byte{},
			Signer: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		}

		_, err := EncodeSingleEcdsaSignature(sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
	})

	t.Run("zero signer", func(t *testing.T) {
		sig := Data{
			R:      [32]byte{0x01},
			S:      [32]byte{0x02},
			Signer: common.Address{},
		}

		_, err := EncodeSingleEcdsaSignature(sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signer address cannot be zero")
	})
}

func TestDecodeSingleSignature(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		expectedR := [32]byte{0x01}
		expectedS := [32]byte{0x02}
		expectedSigner := common.HexToAddress("0x1234567890123456789012345678901234567890")

		data := make([]byte, SingleEcdsaSignatureSize)
		copy(data[0:32], expectedR[:])
		copy(data[32:64], expectedS[:])
		copy(data[64:84], expectedSigner[:])

		r, s, signer, err := DecodeSingleEcdsaSignature(data)
		require.NoError(t, err)
		require.Equal(t, expectedR, r)
		require.Equal(t, expectedS, s)
		require.Equal(t, expectedSigner, signer)
	})

	t.Run("wrong length", func(t *testing.T) {
		data := make([]byte, SingleEcdsaSignatureSize-1)
		_, _, _, err := DecodeSingleEcdsaSignature(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature data must be exactly 84 bytes")
	})

	t.Run("zero R", func(t *testing.T) {
		data := make([]byte, SingleEcdsaSignatureSize)
		s := [32]byte{0x02}
		copy(data[32:64], s[:])
		signer := common.HexToAddress("0x1234567890123456789012345678901234567890")
		copy(data[64:84], signer[:])

		_, _, _, err := DecodeSingleEcdsaSignature(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
	})

	t.Run("zero S", func(t *testing.T) {
		data := make([]byte, SingleEcdsaSignatureSize)
		r := [32]byte{0x01}
		copy(data[0:32], r[:])
		signer := common.HexToAddress("0x1234567890123456789012345678901234567890")
		copy(data[64:84], signer[:])

		_, _, _, err := DecodeSingleEcdsaSignature(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
	})

	t.Run("zero signer", func(t *testing.T) {
		data := make([]byte, SingleEcdsaSignatureSize)
		r := [32]byte{0x01}
		copy(data[0:32], r[:])
		s := [32]byte{0x02}
		copy(data[32:64], s[:])

		_, _, _, err := DecodeSingleEcdsaSignature(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signer address cannot be zero")
	})
}

func TestSingleSignatureRoundTrip(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hash := Keccak256([]byte("test message"))

	r, s, addr, err := SignV27(hash[:], privateKey)
	require.NoError(t, err)

	sig := Data{
		R:      r,
		S:      s,
		Signer: addr,
	}

	encoded, err := EncodeSingleEcdsaSignature(sig)
	require.NoError(t, err)

	decodedR, decodedS, decodedSigner, err := DecodeSingleEcdsaSignature(encoded)
	require.NoError(t, err)

	require.Equal(t, sig.R, decodedR)
	require.Equal(t, sig.S, decodedS)
	require.Equal(t, sig.Signer, decodedSigner)
}
