package commit

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func TestValidateSignerAddress(t *testing.T) {
	const configured = "0x1111111111111111111111111111111111111111"

	tests := []struct {
		name    string
		actual  common.Address
		wantErr bool
	}{
		{
			name:   "imported key matches signer_address",
			actual: common.HexToAddress(configured),
		},
		{
			name:    "wrong imported key is rejected",
			actual:  common.HexToAddress("0x2222222222222222222222222222222222222222"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignerAddress(configured, protocol.UnknownAddress(tt.actual.Bytes()))
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorContains(t, err, "signer_address")
			require.ErrorContains(t, err, "[key_import]")
			require.ErrorContains(t, err, tt.actual.Hex())
		})
	}

	t.Run("malformed signer_address is rejected", func(t *testing.T) {
		actual := protocol.UnknownAddress(common.HexToAddress(configured).Bytes())
		tests := []struct {
			name       string
			configured string
		}{
			{name: "missing 0x prefix", configured: "1111111111111111111111111111111111111111"},
			{name: "short address", configured: "0x1111"},
			{name: "odd-length hex", configured: "0x111"},
			{name: "non-hex character", configured: "0x111111111111111111111111111111111111111g"},
			{name: "surrounding whitespace", configured: " 0x1111111111111111111111111111111111111111 "},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateSignerAddress(tt.configured, actual)
				require.Error(t, err)
				require.ErrorContains(t, err, "invalid signer_address")
				require.ErrorContains(t, err, tt.configured)
			})
		}
	})

	t.Run("generated key is rejected when job expects imported key", func(t *testing.T) {
		generatedKey, err := crypto.GenerateKey()
		require.NoError(t, err)
		generatedAddress := crypto.PubkeyToAddress(generatedKey.PublicKey)
		actual := protocol.UnknownAddress(generatedAddress.Bytes())

		err = ValidateSignerAddress(configured, actual)
		require.Error(t, err)
		require.ErrorContains(t, err, "signer_address")
		require.ErrorContains(t, err, "[key_import]")
		require.ErrorContains(t, err, actual.String())
	})
}

func TestECDSASigner_Sign(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	signer := &ECDSASigner{
		privateKey: privateKey,
	}

	hash := crypto.Keccak256([]byte("test message"))
	var hashArray [32]byte
	copy(hashArray[:], hash[:])

	signature, err := signer.Sign(hash)
	require.NoError(t, err)
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 84 bytes (32 R + 32 S + 20 Signer)")

	r, s, err := protocol.DecodeSingleECDSASignature(signature)
	require.NoError(t, err)

	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	signerAddr, err := protocol.RecoverECDSASigner(hashArray, r, s)
	require.NoError(t, err)
	require.Equal(t, expectedAddr, signerAddr, "signer address should match")

	require.NotEqual(t, [32]byte{}, r, "R should not be zero")
	require.NotEqual(t, [32]byte{}, s, "S should not be zero")
}

func TestECDSASigner_SignDifferentMessages(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	signer := &ECDSASigner{
		privateKey: privateKey,
	}

	hash1 := crypto.Keccak256([]byte("message 1"))
	sig1, err := signer.Sign(hash1)
	require.NoError(t, err)

	hash2 := crypto.Keccak256([]byte("message 2"))
	sig2, err := signer.Sign(hash2)
	require.NoError(t, err)

	require.NotEqual(t, sig1, sig2, "different messages should produce different signatures")
}

func TestECDSASigner_SignSameMessage(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	signer := &ECDSASigner{
		privateKey: privateKey,
	}

	hash := crypto.Keccak256([]byte("test message"))

	sig1, err := signer.Sign(hash)
	require.NoError(t, err)

	sig2, err := signer.Sign(hash)
	require.NoError(t, err)

	require.Equal(t, sig1, sig2, "same message should produce same signature")
}

func TestNewECDSAMessageSigner(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := crypto.FromECDSA(privateKey)

	signer, pubKey, addr, err := NewECDSAMessageSigner(privateKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, pubKey)

	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	require.Equal(t, expectedAddr[:], []byte(addr))
}

func TestNewECDSAMessageSignerFromString(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := "0x" + hex.EncodeToString(privateKeyBytes)

	signer, pubKey, addr, err := NewECDSAMessageSignerFromString(privateKeyHex)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, pubKey)

	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	require.Equal(t, expectedAddr[:], []byte(addr))
}

type mockKeystoreSigner struct {
	privateKey *ecdsa.PrivateKey
}

func (m *mockKeystoreSigner) Sign(data []byte) ([]byte, error) {
	return crypto.Sign(data, m.privateKey)
}

func TestECDSASignerWithKeystoreSigner_Sign(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	mockSigner := &mockKeystoreSigner{
		privateKey: privateKey,
	}

	signer := NewECDSASignerWithKeystoreSigner(mockSigner)

	hash := crypto.Keccak256([]byte("test message"))
	var hashArray [32]byte
	copy(hashArray[:], hash[:])
	signature, err := signer.Sign(hash)
	require.NoError(t, err)
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 84 bytes (32 R + 32 S + 20 Signer)")

	r, s, err := protocol.DecodeSingleECDSASignature(signature)
	require.NoError(t, err)

	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	signerAddr, err := protocol.RecoverECDSASigner(hashArray, r, s)
	require.NoError(t, err)
	require.Equal(t, expectedAddr, signerAddr, "signer address should match")

	require.NotEqual(t, [32]byte{}, r, "R should not be zero")
	require.NotEqual(t, [32]byte{}, s, "S should not be zero")
}

const (
	keyName  = "test-key"
	password = "test-password"
)

// createTestKeystore creates an in-memory keystore with a key for testing.
func createTestKeystore(t *testing.T, keyName string) (keystore.Keystore, []byte) {
	t.Helper()
	ctx := context.Background()

	ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), password)
	require.NoError(t, err)

	// Create a key in the keystore
	createResp, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: keyName, KeyType: keystore.ECDSA_S256},
		},
	})
	require.NoError(t, err)
	require.Len(t, createResp.Keys, 1)

	return ks, createResp.Keys[0].KeyInfo.PublicKey
}

func TestKeystoreSignerAdapter_Sign(t *testing.T) {
	keyName := "test-key"
	ks, pubKeyBytes := createTestKeystore(t, keyName)

	adapter := NewKeystoreSignerAdapter(ks, keyName)

	// KeystoreSignerAdapter.Sign expects a 32-byte hash
	hash := crypto.Keccak256([]byte("test message"))

	signature, err := adapter.Sign(hash)
	require.NoError(t, err)
	require.Len(t, signature, 65, "keystore signature should be 65 bytes (R + S + V)")

	// Verify the signature is valid
	pubKey, err := crypto.SigToPub(hash, signature)
	require.NoError(t, err)

	expectedPubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	require.NoError(t, err)
	require.Equal(t, *expectedPubKey, *pubKey, "recovered public key should match")
}

func TestKeystoreSignerAdapter_SignDifferentMessages(t *testing.T) {
	ks, _ := createTestKeystore(t, keyName)

	adapter := NewKeystoreSignerAdapter(ks, keyName)

	hash1 := crypto.Keccak256([]byte("message 1"))
	sig1, err := adapter.Sign(hash1)
	require.NoError(t, err)

	hash2 := crypto.Keccak256([]byte("message 2"))
	sig2, err := adapter.Sign(hash2)
	require.NoError(t, err)

	require.NotEqual(t, sig1, sig2, "different messages should produce different signatures")
}

func TestKeystoreSignerAdapter_WithECDSASignerWithKeystoreSigner(t *testing.T) {
	// This test verifies the full chain: KeystoreSignerAdapter -> ECDSASignerWithKeystoreSigner
	ks, pubKeyBytes := createTestKeystore(t, keyName)

	adapter := NewKeystoreSignerAdapter(ks, keyName)
	signer := NewECDSASignerWithKeystoreSigner(adapter)

	hash := crypto.Keccak256([]byte("test message"))
	var hashArray [32]byte
	copy(hashArray[:], hash[:])
	signature, err := signer.Sign(hash)
	require.NoError(t, err)
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 84 bytes (32 R + 32 S + 20 Signer)")

	r, s, err := protocol.DecodeSingleECDSASignature(signature)
	require.NoError(t, err)

	expectedPubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	require.NoError(t, err)
	expectedAddr := crypto.PubkeyToAddress(*expectedPubKey)
	signerAddr, err := protocol.RecoverECDSASigner(hashArray, r, s)
	require.NoError(t, err)
	require.Equal(t, expectedAddr, signerAddr, "signer address should match")

	require.NotEqual(t, [32]byte{}, r, "R should not be zero")
	require.NotEqual(t, [32]byte{}, s, "S should not be zero")
}

func TestNewSignerFromKeystore(t *testing.T) {
	ks, _ := createTestKeystore(t, keyName)

	ctx := context.Background()
	signer, _, address, err := NewSignerFromKeystore(ctx, ks, keyName)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test that the signer actually works
	hash := crypto.Keccak256([]byte("test message"))
	var hashArray [32]byte
	copy(hashArray[:], hash[:])
	signature, err := signer.Sign(hash)
	require.NoError(t, err)
	require.Len(t, signature, protocol.SingleECDSASignatureSize)

	r, s, err := protocol.DecodeSingleECDSASignature(signature)
	require.NoError(t, err)
	signerAddr, err := protocol.RecoverECDSASigner(hashArray, r, s)
	require.NoError(t, err)
	require.Equal(t, address.Bytes(), signerAddr.Bytes())
	require.NotEqual(t, [32]byte{}, r)
	require.NotEqual(t, [32]byte{}, s)
}

func TestNewSignerFromKeystore_KeyNotFound(t *testing.T) {
	ks, _ := createTestKeystore(t, keyName)

	ctx := context.Background()
	_, _, _, err := NewSignerFromKeystore(ctx, ks, "non-existent-key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}
