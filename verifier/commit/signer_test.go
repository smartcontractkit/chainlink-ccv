package commit

import (
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestECDSASigner_Sign(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	signer := &ECDSASigner{
		privateKey: privateKey,
	}

	hash := crypto.Keccak256([]byte("test message"))

	signature, err := signer.Sign(hash)
	require.NoError(t, err)
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 84 bytes (32 R + 32 S + 20 Signer)")

	r, s, signerAddr, err := protocol.DecodeSingleECDSASignature(signature)
	require.NoError(t, err)

	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
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

	signature, err := signer.Sign(hash)
	require.NoError(t, err)
	require.Len(t, signature, protocol.SingleECDSASignatureSize, "signature should be 84 bytes (32 R + 32 S + 20 Signer)")

	r, s, signerAddr, err := protocol.DecodeSingleECDSASignature(signature)
	require.NoError(t, err)

	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	require.Equal(t, expectedAddr, signerAddr, "signer address should match")

	require.NotEqual(t, [32]byte{}, r, "R should not be zero")
	require.NotEqual(t, [32]byte{}, s, "S should not be zero")
}
