package kmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/freeport"
	"github.com/stretchr/testify/require"
)

func TestServer_Sign(t *testing.T) {
	memoryStorage := keystore.NewMemoryStorage()
	keyStore, err := keystore.LoadKeystore(t.Context(), memoryStorage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)

	// Create a CSA (Ed25519) and an Eth key (SECP256K1)
	csaKeyName := "csa-key"
	ethKeyName := "eth-key"
	keysResponse, err := keyStore.CreateKeys(t.Context(), keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: csaKeyName, KeyType: keystore.Ed25519},
			{KeyName: ethKeyName, KeyType: keystore.ECDSA_S256},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 2, len(keysResponse.Keys))
	require.Equal(t, csaKeyName, keysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keystore.Ed25519, keysResponse.Keys[0].KeyInfo.KeyType)
	require.Equal(t, ethKeyName, keysResponse.Keys[1].KeyInfo.Name)
	require.Equal(t, keystore.ECDSA_S256, keysResponse.Keys[1].KeyInfo.KeyType)

	port := freeport.GetOne(t)
	server := NewServer(keyStore, port, logger.Test(t))
	require.NoError(t, server.Start())
	t.Cleanup(func() {
		require.NoError(t, server.Stop())
	})

	// Sign data with the CSA key through the API.
	csaKey := keysResponse.Keys[0]
	data := crypto.Keccak256([]byte("test-data"))
	signRequest, err := json.Marshal(keystore.SignRequest{
		KeyName: csaKeyName,
		Data:    data,
	})
	require.NoError(t, err)
	// Create the request
	req, err := http.NewRequestWithContext(t.Context(), "POST", fmt.Sprintf("http://localhost:%d/signer/sign", port), bytes.NewBuffer(signRequest))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Parse the response
	var signResponse keystore.SignResponse
	err = json.NewDecoder(resp.Body).Decode(&signResponse)
	require.NoError(t, err)
	require.NotEmpty(t, signResponse.Signature)

	// Verify it using the keyStore
	verifyResponse, err := keyStore.Verify(t.Context(), keystore.VerifyRequest{
		KeyType:   keystore.Ed25519,
		PublicKey: csaKey.KeyInfo.PublicKey,
		Data:      data,
		Signature: signResponse.Signature,
	})
	require.NoError(t, err)
	require.True(t, verifyResponse.Valid)

	// Sign data with the Eth key through the API
	ethKey := keysResponse.Keys[1]
	signRequest, err = json.Marshal(keystore.SignRequest{
		KeyName: ethKeyName,
		Data:    data,
	})
	require.NoError(t, err)
	req, err = http.NewRequestWithContext(t.Context(), "POST", fmt.Sprintf("http://localhost:%d/signer/sign", port), bytes.NewBuffer(signRequest))
	require.NoError(t, err)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Parse the response
	var ethSignResponse keystore.SignResponse
	err = json.NewDecoder(resp.Body).Decode(&ethSignResponse)
	require.NoError(t, err)
	require.NotEmpty(t, ethSignResponse.Signature)

	// Verify it using the keyStore
	verifyResponse, err = keyStore.Verify(t.Context(), keystore.VerifyRequest{
		KeyType:   keystore.ECDSA_S256,
		PublicKey: ethKey.KeyInfo.PublicKey,
		Data:      data,
		Signature: ethSignResponse.Signature,
	})
	require.NoError(t, err)
	require.True(t, verifyResponse.Valid)
}
