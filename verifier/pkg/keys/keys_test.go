package keys

import (
	"context"
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
	assert.NotNil(t, keyPair.CSAPrivateKey)
	assert.Equal(t, ed25519.PublicKeySize, len(keyPair.CSAPublicKey))
	assert.Equal(t, ed25519.PrivateKeySize, len(keyPair.CSAPrivateKey))

	// Second call should return the same keys
	keyPair2, err := GetOrCreateKeys(ctx, ks)
	require.NoError(t, err)
	require.NotNil(t, keyPair2)

	assert.Equal(t, keyPair.SigningAddress, keyPair2.SigningAddress)
	assert.Equal(t, keyPair.CSAPublicKey, keyPair2.CSAPublicKey)
	assert.Equal(t, keyPair.CSAPrivateKey, keyPair2.CSAPrivateKey)
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

	// Verify the CSA key can sign and verify
	testMessage := []byte("test message for CSA signing")
	signature := ed25519.Sign(keyPair.CSAPrivateKey, testMessage)
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
