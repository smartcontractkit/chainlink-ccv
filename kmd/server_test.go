package kmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/freeport"
)

const testKeystorePassword = "test-password"
const healthPollInterval = 50 * time.Millisecond
const healthPollTimeout = 5 * time.Second

// testKeystore returns a new in-memory keystore loaded with fast scrypt params.
func testKeystore(t *testing.T) keystore.Keystore {
	t.Helper()
	memoryStorage := keystore.NewMemoryStorage()
	keyStore, err := keystore.LoadKeystore(t.Context(), memoryStorage, testKeystorePassword, keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)
	return keyStore
}

// startServerWithHealthCheck starts the server and blocks until the /health endpoint returns 200.
// Caller must not call server.Stop(); cleanup is registered via t.Cleanup.
func startServerWithHealthCheck(t *testing.T, keyStore keystore.Keystore) int {
	t.Helper()
	port := freeport.GetOne(t)
	server := NewServer(keyStore, port, logger.Test(t))
	require.NoError(t, server.Start())
	t.Cleanup(func() {
		require.NoError(t, server.Stop())
	})
	waitForHealthy(t, port)
	return port
}

func waitForHealthy(t *testing.T, port int) {
	t.Helper()
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	deadline := time.Now().Add(healthPollTimeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + HealthEndpoint)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(healthPollInterval)
	}
	t.Fatalf("server at %s did not become healthy within %v", baseURL, healthPollTimeout)
}

// postJSON sends a POST request with JSON body to the given endpoint. The returned response body must be closed by the caller.
func postJSON(t *testing.T, port int, endpoint string, body interface{}) *http.Response {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	url := fmt.Sprintf("http://localhost:%d%s", port, endpoint)
	req, err := http.NewRequestWithContext(t.Context(), "POST", url, bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestServer_Sign(t *testing.T) {
	keyStore := testKeystore(t)

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

	port := startServerWithHealthCheck(t, keyStore)

	// Sign data with the CSA key through the API.
	csaKey := keysResponse.Keys[0]
	data := crypto.Keccak256([]byte("test-data"))
	resp1 := postJSON(t, port, SignEndpoint, keystore.SignRequest{KeyName: csaKeyName, Data: data})
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode, "sign request failed: %s", resp1.Status)
	var signResponse keystore.SignResponse
	require.NoError(t, json.NewDecoder(resp1.Body).Decode(&signResponse))
	require.NotEmpty(t, signResponse.Signature)

	verifyResponse, err := keyStore.Verify(t.Context(), keystore.VerifyRequest{
		KeyType:   keystore.Ed25519,
		PublicKey: csaKey.KeyInfo.PublicKey,
		Data:      data,
		Signature: signResponse.Signature,
	})
	require.NoError(t, err)
	require.True(t, verifyResponse.Valid)

	// Sign data with the Eth key through the API.
	ethKey := keysResponse.Keys[1]
	resp2 := postJSON(t, port, SignEndpoint, keystore.SignRequest{KeyName: ethKeyName, Data: data})
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "sign request failed: %s", resp2.Status)
	var ethSignResponse keystore.SignResponse
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&ethSignResponse))
	require.NotEmpty(t, ethSignResponse.Signature)

	verifyResponse, err = keyStore.Verify(t.Context(), keystore.VerifyRequest{
		KeyType:   keystore.ECDSA_S256,
		PublicKey: ethKey.KeyInfo.PublicKey,
		Data:      data,
		Signature: ethSignResponse.Signature,
	})
	require.NoError(t, err)
	require.True(t, verifyResponse.Valid)
}

func TestServer_GetKeys(t *testing.T) {
	keyStore := testKeystore(t)

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

	port := startServerWithHealthCheck(t, keyStore)

	resp := postJSON(t, port, GetKeysEndpoint, keystore.GetKeysRequest{KeyNames: []string{csaKeyName, ethKeyName}})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "get keys request failed: %s", resp.Status)
	var getKeysResponse keystore.GetKeysResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getKeysResponse))
	require.Equal(t, 2, len(getKeysResponse.Keys))
	require.Equal(t, csaKeyName, getKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keystore.Ed25519, getKeysResponse.Keys[0].KeyInfo.KeyType)
	require.Equal(t, ethKeyName, getKeysResponse.Keys[1].KeyInfo.Name)
	require.Equal(t, keystore.ECDSA_S256, getKeysResponse.Keys[1].KeyInfo.KeyType)
}

func TestServer_CreateKeys(t *testing.T) {
	keyStore := testKeystore(t)
	port := startServerWithHealthCheck(t, keyStore)

	keyName := testKeyName
	keyType := keystore.ECDSA_S256

	resp1 := postJSON(t, port, CreateEndpoint, keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: keyName, KeyType: keyType},
		},
	})
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode, "create keys request failed: %s", resp1.Status)
	var createKeysResponse keystore.CreateKeysResponse
	require.NoError(t, json.NewDecoder(resp1.Body).Decode(&createKeysResponse))
	require.Equal(t, 1, len(createKeysResponse.Keys))
	require.Equal(t, keyName, createKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, createKeysResponse.Keys[0].KeyInfo.KeyType)

	resp2 := postJSON(t, port, GetKeysEndpoint, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "get keys request failed: %s", resp2.Status)
	var getKeysResponse keystore.GetKeysResponse
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&getKeysResponse))
	require.Equal(t, 1, len(getKeysResponse.Keys))
	require.Equal(t, keyName, getKeysResponse.Keys[0].KeyInfo.Name)
	require.Equal(t, keyType, getKeysResponse.Keys[0].KeyInfo.KeyType)
}
