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
	for i := range 3 {
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
	rs := make([][32]byte, 0, len(privateKeys))
	ss := make([][32]byte, 0, len(privateKeys))
	for _, pk := range privateKeys {
		r, s, _, err := SignV27(hashArray[:], pk)
		require.NoError(t, err)
		rs = append(rs, r)
		ss = append(ss, s)
	}

	// Recover signers
	recoveredAddresses, err := RecoverECDSASigners(hashArray, rs, ss)
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

		encoded, err := EncodeSingleECDSASignature(sig)
		require.NoError(t, err)
		require.Len(t, encoded, SingleECDSASignatureSize)
		require.Equal(t, sig.R[:], encoded[0:32])
		require.Equal(t, sig.S[:], encoded[32:64])
	})

	t.Run("zero R", func(t *testing.T) {
		sig := Data{
			R:      [32]byte{},
			S:      [32]byte{0x02},
			Signer: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		}

		_, err := EncodeSingleECDSASignature(sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
	})

	t.Run("zero S", func(t *testing.T) {
		sig := Data{
			R:      [32]byte{0x01},
			S:      [32]byte{},
			Signer: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		}

		_, err := EncodeSingleECDSASignature(sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
	})

	t.Run("zero signer", func(t *testing.T) {
		sig := Data{
			R:      [32]byte{0x01},
			S:      [32]byte{0x02},
			Signer: common.Address{},
		}

		_, err := EncodeSingleECDSASignature(sig)
		require.NoError(t, err, "signer address should not be included in the encoded signature")
	})
}

func TestDecodeSingleSignature(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		expectedR := [32]byte{0x01}
		expectedS := [32]byte{0x02}

		data := make([]byte, SingleECDSASignatureSize)
		copy(data[0:32], expectedR[:])
		copy(data[32:64], expectedS[:])

		r, s, err := DecodeSingleECDSASignature(data)
		require.NoError(t, err)
		require.Equal(t, expectedR, r)
		require.Equal(t, expectedS, s)
	})

	t.Run("wrong length", func(t *testing.T) {
		data := make([]byte, SingleECDSASignatureSize-1)
		_, _, err := DecodeSingleECDSASignature(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature data must be exactly 64 bytes")
	})

	t.Run("zero R", func(t *testing.T) {
		data := make([]byte, SingleECDSASignatureSize)
		s := [32]byte{0x02}
		copy(data[32:64], s[:])

		_, _, err := DecodeSingleECDSASignature(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
	})

	t.Run("zero S", func(t *testing.T) {
		data := make([]byte, SingleECDSASignatureSize)
		r := [32]byte{0x01}
		copy(data[0:32], r[:])

		_, _, err := DecodeSingleECDSASignature(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature R and S cannot be zero")
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

	encoded, err := EncodeSingleECDSASignature(sig)
	require.NoError(t, err)

	decodedR, decodedS, err := DecodeSingleECDSASignature(encoded)
	require.NoError(t, err)

	require.Equal(t, sig.R, decodedR)
	require.Equal(t, sig.S, decodedS)
}

// TestLeftPad32_InputTooLong verifies that leftPad32 returns an error when input exceeds 32 bytes.
func TestLeftPad32_InputTooLong(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectError bool
	}{
		{
			name:        "32_bytes_valid",
			input:       make([]byte, 32),
			expectError: false,
		},
		{
			name:        "1_byte_valid",
			input:       []byte{0x01},
			expectError: false,
		},
		{
			name:        "empty_valid",
			input:       []byte{},
			expectError: false,
		},
		{
			name:        "33_bytes_invalid",
			input:       make([]byte, 33),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := leftPad32(tt.input)
			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, result)
				require.Contains(t, err.Error(), "slice too long")
			} else {
				require.NoError(t, err)
				require.Len(t, result, 32)
				// Verify the input is right-aligned in the output
				expectedStart := 32 - len(tt.input)
				require.Equal(t, tt.input, result[expectedStart:])
				// Verify left padding is zeros
				for i := range expectedStart {
					require.Equal(t, byte(0), result[i])
				}
			}
		})
	}
}
