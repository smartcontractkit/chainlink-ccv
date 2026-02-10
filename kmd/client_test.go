package kmd

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/freeport"
)

const testKeyName = "test-key"

func TestClient_Sign(t *testing.T) {
	memoryStorage := keystore.NewMemoryStorage()
	keyStore, err := keystore.LoadKeystore(t.Context(), memoryStorage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	// Create a test key
	keyName := testKeyName
	keyType := keystore.ECDSA_S256
	keysResponse, err := keyStore.CreateKeys(t.Context(), keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: keyName, KeyType: keyType},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(keysResponse.Keys))
	require.Equal(t, keyName, keysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, keysResponse.Keys[0].KeyInfo.KeyType)

	port := freeport.GetOne(t)
	server := NewServer(keyStore, port, logger.Test(t))
	require.NoError(t, server.Start())
	t.Cleanup(func() {
		require.NoError(t, server.Stop())
	})

	client := NewClient(fmt.Sprintf("http://localhost:%d", port))
	data := crypto.Keccak256([]byte("test-data"))
	signRequest := keystore.SignRequest{
		KeyName: keyName,
		Data:    data,
	}
	signResponse, err := client.Sign(t.Context(), signRequest)
	require.NoError(t, err)
	require.NotEmpty(t, signResponse.Signature)

	// Verify the signature
	verifyResponse, err := keyStore.Verify(t.Context(), keystore.VerifyRequest{
		KeyType:   keyType,
		PublicKey: keysResponse.Keys[0].KeyInfo.PublicKey,
		Data:      data,
		Signature: signResponse.Signature,
	})
	require.NoError(t, err)
	require.True(t, verifyResponse.Valid)
}

func TestClient_GetKeys(t *testing.T) {
	memoryStorage := keystore.NewMemoryStorage()
	keyStore, err := keystore.LoadKeystore(t.Context(), memoryStorage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	// Create a test key
	keyName := testKeyName
	keyType := keystore.ECDSA_S256
	keysResponse, err := keyStore.CreateKeys(t.Context(), keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: keyName, KeyType: keyType},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(keysResponse.Keys))
	require.Equal(t, keyName, keysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, keysResponse.Keys[0].KeyInfo.KeyType)

	port := freeport.GetOne(t)
	server := NewServer(keyStore, port, logger.Test(t))
	require.NoError(t, server.Start())
	t.Cleanup(func() {
		require.NoError(t, server.Stop())
	})

	client := NewClient(fmt.Sprintf("http://localhost:%d", port))
	getKeysRequest := keystore.GetKeysRequest{
		KeyNames: []string{keyName},
	}
	getKeysResponse, err := client.GetKeys(t.Context(), getKeysRequest)
	require.NoError(t, err)
	require.Equal(t, 1, len(getKeysResponse.Keys))
	require.Equal(t, keyName, getKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, getKeysResponse.Keys[0].KeyInfo.KeyType)
}

func TestClient_CreateKeys(t *testing.T) {
	memoryStorage := keystore.NewMemoryStorage()
	keyStore, err := keystore.LoadKeystore(t.Context(), memoryStorage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	port := freeport.GetOne(t)
	server := NewServer(keyStore, port, logger.Test(t))
	require.NoError(t, server.Start())
	t.Cleanup(func() {
		require.NoError(t, server.Stop())
	})

	// Create a test key through the API
	keyName := testKeyName
	keyType := keystore.ECDSA_S256
	client := NewClient(fmt.Sprintf("http://localhost:%d", port))
	createKeysResponse, err := client.CreateKeys(t.Context(), keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: keyName, KeyType: keyType},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(createKeysResponse.Keys))
	require.Equal(t, keyName, createKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, createKeysResponse.Keys[0].KeyInfo.KeyType)

	// Get the keys that were just created
	getKeysRequest := keystore.GetKeysRequest{
		KeyNames: []string{keyName},
	}
	getKeysResponse, err := client.GetKeys(t.Context(), getKeysRequest)
	require.NoError(t, err)
	require.Equal(t, 1, len(getKeysResponse.Keys))
	require.Equal(t, keyName, getKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, getKeysResponse.Keys[0].KeyInfo.KeyType)
}
