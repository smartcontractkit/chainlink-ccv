package kmd

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/freeport"
	"github.com/stretchr/testify/require"
)

func TestClient_Sign(t *testing.T) {
	memoryStorage := keystore.NewMemoryStorage()
	keyStore, err := keystore.LoadKeystore(t.Context(), memoryStorage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	// Create a test key
	keyName := "test-key"
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
