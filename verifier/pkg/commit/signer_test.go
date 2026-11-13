package commit

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func TestValidateSignerAddress(t *testing.T) {
	const configured = "0x1111111111111111111111111111111111111111"

	evmAddress := protocol.UnknownAddress(common.HexToAddress(configured).Bytes())
	wrongAddress := protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes())

	cantonKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	cantonPubKey := crypto.FromECDSAPub(&cantonKey.PublicKey)
	cantonAddress := protocol.UnknownAddress(crypto.PubkeyToAddress(cantonKey.PublicKey).Bytes())
	cantonConfigured := hex.EncodeToString(cantonPubKey)
	cantonCompressed := crypto.CompressPubkey(&cantonKey.PublicKey)

	t.Run("matching signer_address is accepted", func(t *testing.T) {
		tests := []struct {
			name       string
			configured string
			actual     protocol.UnknownAddress
		}{
			{name: "0x-prefixed EVM address", configured: configured, actual: evmAddress},
			{name: "unprefixed EVM address", configured: strings.TrimPrefix(configured, "0x"), actual: evmAddress},
			{name: "uppercase hex digits", configured: "0x" + strings.ToUpper(strings.TrimPrefix(configured, "0x")), actual: evmAddress},
			{name: "unprefixed Canton public key", configured: cantonConfigured, actual: cantonPubKey},
			{name: "0x-prefixed Canton public key", configured: "0x" + cantonConfigured, actual: cantonPubKey},
			{name: "address configured, public key from keystore", configured: cantonAddress.String(), actual: cantonPubKey},
			{name: "public key configured, address from keystore", configured: cantonConfigured, actual: cantonAddress},
			{name: "compressed public key configured, uncompressed from keystore", configured: hex.EncodeToString(cantonCompressed), actual: cantonPubKey},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require.NoError(t, ValidateSignerAddress(tt.configured, tt.actual))
			})
		}
	})

	t.Run("mismatched signer_address is rejected", func(t *testing.T) {
		tests := []struct {
			name       string
			configured string
			actual     protocol.UnknownAddress
			wantInErr  string
		}{
			{
				name:       "wrong EVM address",
				configured: configured,
				actual:     wrongAddress,
				wantInErr:  wrongAddress.String(),
			},
			{
				name:       "unprefixed but wrong EVM address",
				configured: strings.TrimPrefix(configured, "0x"),
				actual:     wrongAddress,
				wantInErr:  wrongAddress.String(),
			},
			{
				name:       "short address is compared, not reshaped",
				configured: "0x1111",
				actual:     evmAddress,
				wantInErr:  evmAddress.String(),
			},
			{
				name:       "trailing public key bytes do not match the full key",
				configured: hex.EncodeToString(cantonPubKey[len(cantonPubKey)-common.AddressLength:]),
				actual:     cantonPubKey,
				wantInErr:  protocol.UnknownAddress(cantonPubKey).String(),
			},
			{
				name:       "Canton public key configured, unrelated address from keystore",
				configured: cantonConfigured,
				actual:     evmAddress,
				wantInErr:  evmAddress.String(),
			},
			{
				name:       "EVM address configured, unrelated public key from keystore",
				configured: configured,
				actual:     cantonPubKey,
				wantInErr:  protocol.UnknownAddress(cantonPubKey).String(),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateSignerAddress(tt.configured, tt.actual)
				require.Error(t, err)
				require.ErrorContains(t, err, "signer_address")
				require.ErrorContains(t, err, "[key_import]")
				require.ErrorContains(t, err, tt.wantInErr)
			})
		}
	})

	t.Run("malformed signer_address is rejected", func(t *testing.T) {
		tests := []struct {
			name       string
			configured string
		}{
			{name: "odd-length hex", configured: "0x111"},
			{name: "non-hex character", configured: "0x111111111111111111111111111111111111111g"},
			{name: "surrounding whitespace", configured: " 0x1111111111111111111111111111111111111111 "},
			{name: "whole-word whitespace", configured: "not-hex"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateSignerAddress(tt.configured, evmAddress)
				require.Error(t, err)
				require.ErrorContains(t, err, "invalid signer_address")
				require.ErrorContains(t, err, tt.configured)
			})
		}
	})

	t.Run("empty signer_address is rejected as forgotten", func(t *testing.T) {
		err := ValidateSignerAddress("", evmAddress)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid signer_address")
	})

	t.Run("auto signer_address adopts the keystore address", func(t *testing.T) {
		for _, tt := range []struct {
			name   string
			actual common.Address
		}{
			{name: "matches actual", actual: common.HexToAddress(configured)},
			{name: "any keystore address", actual: common.HexToAddress("0x3333333333333333333333333333333333333333")},
		} {
			t.Run(tt.name, func(t *testing.T) {
				require.NoError(t, ValidateSignerAddress(AutoSignerAddress, tt.actual.Bytes()))
			})
		}
	})

	t.Run("generated key is rejected when job expects imported key", func(t *testing.T) {
		generatedKey, err := crypto.GenerateKey()
		require.NoError(t, err)
		actual := crypto.PubkeyToAddress(generatedKey.PublicKey).Bytes()

		err = ValidateSignerAddress(configured, actual)
		require.Error(t, err)
		require.ErrorContains(t, err, "signer_address")
		require.ErrorContains(t, err, "[key_import]")
		require.ErrorContains(t, err, protocol.UnknownAddress(actual).String())
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
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 64 bytes (32 R + 32 S)")

	expectedR, expectedS, _, err := protocol.SignV27(hash, privateKey)
	require.NoError(t, err)
	expectedSignature, err := protocol.EncodeSingleECDSASignature(protocol.Data{R: expectedR, S: expectedS})
	require.NoError(t, err)
	require.Equal(t, expectedSignature, signature)

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
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 64 bytes (32 R + 32 S)")

	expectedR, expectedS, _, err := protocol.SignV27WithKeystoreSigner(hash, mockSigner)
	require.NoError(t, err)
	expectedSignature, err := protocol.EncodeSingleECDSASignature(protocol.Data{R: expectedR, S: expectedS})
	require.NoError(t, err)
	require.Equal(t, expectedSignature, signature)

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
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 64 bytes (32 R + 32 S)")

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

func TestNewECDSASignerFromKeystore(t *testing.T) {
	ks, expectedPublicKey := createTestKeystore(t, keyName)

	ctx := context.Background()
	signer, publicKey, err := NewECDSASignerFromKeystore(ctx, ks, keyName)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.Equal(t, expectedPublicKey, publicKey)
	address, err := EVMAddressFromPublicKey(publicKey)
	require.NoError(t, err)

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

	require.NoError(t, ValidateSignerAddress(hex.EncodeToString(publicKey), publicKey))
	require.NoError(t, ValidateSignerAddress(signerAddr.Hex(), publicKey))

	identity, err := ResolveSignerIdentity(hex.EncodeToString(publicKey), publicKey)
	require.NoError(t, err)
	require.Equal(t, protocol.UnknownAddress(publicKey), identity)
	identity, err = ResolveSignerIdentity(signerAddr.Hex(), publicKey)
	require.NoError(t, err)
	require.Equal(t, address, identity)

	parsedPublicKey, err := crypto.UnmarshalPubkey(publicKey)
	require.NoError(t, err)
	compressedPublicKey := crypto.CompressPubkey(parsedPublicKey)
	identity, err = ResolveSignerIdentity(hex.EncodeToString(compressedPublicKey), publicKey)
	require.NoError(t, err)
	require.Equal(t, protocol.UnknownAddress(compressedPublicKey), identity)
}

func TestResolveSignerIdentityDoesNotDeriveForPublicKey(t *testing.T) {
	publicKey := make([]byte, 65)
	_, err := crypto.UnmarshalPubkey(publicKey)
	require.Error(t, err)

	identity, err := ResolveSignerIdentity(hex.EncodeToString(publicKey), publicKey)
	require.NoError(t, err)
	require.Equal(t, protocol.UnknownAddress(publicKey), identity)
	identity, err = ResolveSignerIdentity(AutoSignerAddress, publicKey)
	require.NoError(t, err)
	require.Equal(t, protocol.UnknownAddress(publicKey), identity)
}

func TestNewSignerFromKeystore(t *testing.T) {
	ks, expectedPublicKey := createTestKeystore(t, keyName)

	_, publicKey, address, err := NewSignerFromKeystore(context.Background(), ks, keyName)
	require.NoError(t, err)
	require.Equal(t, expectedPublicKey, publicKey)
	expectedAddress, err := EVMAddressFromPublicKey(publicKey)
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
}

func TestNewSignerFromKeystore_KeyNotFound(t *testing.T) {
	ks, _ := createTestKeystore(t, keyName)

	ctx := context.Background()
	_, _, _, err := NewSignerFromKeystore(ctx, ks, "non-existent-key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}
