package keys

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

func TestGetOrCreateKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create an in-memory keystore
	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	// First call should create keys
	keyPair, err := GetOrCreateKeys(ctx, ks)
	require.NoError(t, err)
	require.NotNil(t, keyPair)

	// Verify signing address is a valid Ethereum address
	assert.NotEmpty(t, keyPair.SigningAddress)
	assert.True(t, len(keyPair.SigningAddress) == 42, "should be a valid hex address")
	assert.Equal(t, "0x", keyPair.SigningAddress[:2])

	// Verify CSA keys
	assert.NotNil(t, keyPair.CSAPublicKey)
	assert.NotNil(t, keyPair.CSASigner)
	assert.Equal(t, ed25519.PublicKeySize, len(keyPair.CSAPublicKey))

	// Verify signer's public key matches
	signerPubKey := keyPair.CSASigner.Public().(ed25519.PublicKey)
	assert.Equal(t, keyPair.CSAPublicKey, signerPubKey)

	// Second call should return the same keys
	keyPair2, err := GetOrCreateKeys(ctx, ks)
	require.NoError(t, err)
	require.NotNil(t, keyPair2)

	assert.Equal(t, keyPair.SigningAddress, keyPair2.SigningAddress)
	assert.Equal(t, keyPair.CSAPublicKey, keyPair2.CSAPublicKey)
}

func TestGetOrCreateKeys_SigningKeyWorks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create an in-memory keystore
	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	keyPair, err := GetOrCreateKeys(ctx, ks)
	require.NoError(t, err)

	// Verify the signing key can be used to sign
	testData := make([]byte, 32)
	signResp, err := ks.Sign(ctx, keystore.SignRequest{
		KeyName: SigningKeyName,
		Data:    testData,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, signResp.Signature)

	// The signing address should be derivable from the public key
	assert.NotEmpty(t, keyPair.SigningAddress)
}

func TestGetOrCreateKeys_CSAKeyWorks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create an in-memory keystore
	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	keyPair, err := GetOrCreateKeys(ctx, ks)
	require.NoError(t, err)

	// Verify the CSA signer can sign and the signature can be verified
	testMessage := []byte("test message for CSA signing")
	signature, err := keyPair.CSASigner.Sign(nil, testMessage, crypto.Hash(0))
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(keyPair.CSAPublicKey, testMessage, signature))
}

func TestGetSigningAddress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	// Before creating keys, should error
	_, err = GetSigningAddress(ctx, ks)
	require.Error(t, err)

	// Create keys
	keyPair, err := GetOrCreateKeys(ctx, ks)
	require.NoError(t, err)

	// Now should work
	addr, err := GetSigningAddress(ctx, ks)
	require.NoError(t, err)
	assert.Equal(t, keyPair.SigningAddress, addr)
}

func TestGetCSAPublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	// Before creating keys, should error
	_, err = GetCSAPublicKey(ctx, ks)
	require.Error(t, err)

	// Create keys
	keyPair, err := GetOrCreateKeys(ctx, ks)
	require.NoError(t, err)

	// Now should work
	pubKey, err := GetCSAPublicKey(ctx, ks)
	require.NoError(t, err)
	assert.Equal(t, keyPair.CSAPublicKey, pubKey) // Both are ed25519.PublicKey
}
