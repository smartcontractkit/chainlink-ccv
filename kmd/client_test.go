package kmd

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

const testKeyName = "test-key"

func TestClient_Sign(t *testing.T) {
	keyStore := testKeystore(t)

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

	port := startServerWithHealthCheck(t, keyStore)
	client := NewClient(fmt.Sprintf("http://localhost:%d", port))

	data := crypto.Keccak256([]byte("test-data"))
	signResponse, err := client.Sign(t.Context(), keystore.SignRequest{KeyName: keyName, Data: data})
	require.NoError(t, err)
	require.NotEmpty(t, signResponse.Signature)

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
	keyStore := testKeystore(t)

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

	port := startServerWithHealthCheck(t, keyStore)
	client := NewClient(fmt.Sprintf("http://localhost:%d", port))

	getKeysResponse, err := client.GetKeys(t.Context(), keystore.GetKeysRequest{KeyNames: []string{keyName}})
	require.NoError(t, err)
	require.Equal(t, 1, len(getKeysResponse.Keys))
	require.Equal(t, keyName, getKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, getKeysResponse.Keys[0].KeyInfo.KeyType)
}

func TestClient_CreateKeys(t *testing.T) {
	keyStore := testKeystore(t)
	port := startServerWithHealthCheck(t, keyStore)
	client := NewClient(fmt.Sprintf("http://localhost:%d", port))

	keyName := testKeyName
	keyType := keystore.ECDSA_S256
	createKeysResponse, err := client.CreateKeys(t.Context(), keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: keyName, KeyType: keyType},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(createKeysResponse.Keys))
	require.Equal(t, keyName, createKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, createKeysResponse.Keys[0].KeyInfo.KeyType)

	getKeysResponse, err := client.GetKeys(t.Context(), keystore.GetKeysRequest{KeyNames: []string{keyName}})
	require.NoError(t, err)
	require.Equal(t, 1, len(getKeysResponse.Keys))
	require.Equal(t, keyName, getKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, getKeysResponse.Keys[0].KeyInfo.KeyType)
}
