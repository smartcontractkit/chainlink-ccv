package util

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

const (
	keyName  = "test-key"
	password = "test-password"
)

func TestCreateImportData(t *testing.T) {
	// Generate a test private key
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := crypto.FromECDSA(privateKey)

	// Create import data
	importData, err := createImportData(keyName, privateKeyBytes, password)
	require.NoError(t, err)
	require.NotEmpty(t, importData)

	// Verify the import data can be imported by the keystore library
	ctx := context.Background()
	ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), password)
	require.NoError(t, err)

	// Import the key
	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{
			{
				NewKeyName: keyName,
				Data:       importData,
				Password:   password,
			},
		},
	})
	require.NoError(t, err)

	// Verify the key was imported correctly
	keysResp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	require.NoError(t, err)
	require.Len(t, keysResp.Keys, 1)

	keyInfo := keysResp.Keys[0].KeyInfo
	require.Equal(t, keyName, keyInfo.Name)
	require.Equal(t, keystore.ECDSA_S256, keyInfo.KeyType)

	// Verify the public key matches
	expectedPubKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	require.Equal(t, expectedPubKey, keyInfo.PublicKey)
}

func TestCreateImportData_CanSign(t *testing.T) {
	// Generate a test private key
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := crypto.FromECDSA(privateKey)

	// Create import data and import into keystore
	importData, err := createImportData(keyName, privateKeyBytes, password)
	require.NoError(t, err)

	ctx := context.Background()
	ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), password)
	require.NoError(t, err)

	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{
			{
				NewKeyName: keyName,
				Data:       importData,
				Password:   password,
			},
		},
	})
	require.NoError(t, err)

	// Sign some data with the imported key
	hash := crypto.Keccak256([]byte("test message"))
	signResp, err := ks.Sign(ctx, keystore.SignRequest{
		KeyName: keyName,
		Data:    hash,
	})
	require.NoError(t, err)
	require.Len(t, signResp.Signature, 65, "ECDSA signature should be 65 bytes")

	// Verify the signature using the original private key
	pubKey, err := crypto.SigToPub(hash, signResp.Signature)
	require.NoError(t, err)
	require.Equal(t, privateKey.PublicKey, *pubKey, "recovered public key should match")
}

func TestCreateImportData_DifferentPasswords(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := crypto.FromECDSA(privateKey)
	encryptPassword := "encrypt-password"
	wrongPassword := "wrong-password"

	// Create import data with one password
	importData, err := createImportData(keyName, privateKeyBytes, encryptPassword)
	require.NoError(t, err)

	// Try to import with wrong password - should fail
	ctx := context.Background()
	ks, err := keystore.LoadKeystore(ctx, keystore.NewMemoryStorage(), "keystore-password")
	require.NoError(t, err)

	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{
			{
				NewKeyName: keyName,
				Data:       importData,
				Password:   wrongPassword, // Wrong password for import data
			},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "decrypt")
}

func TestProvisionKeystoreKey_WithMemoryStorage(t *testing.T) {
	// This test verifies the ProvisionKeystoreKey logic using memory storage
	// instead of a real database. We test the createImportData + import flow.

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := crypto.FromECDSA(privateKey)
	keyName := "verifier-signing-key"
	keystorePassword := "test-keystore-password"

	ctx := context.Background()

	// Create a memory-based keystore
	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, keystorePassword)
	require.NoError(t, err)

	// Create and import the key (simulating what ProvisionKeystoreKey does)
	importData, err := createImportData(keyName, privateKeyBytes, keystorePassword)
	require.NoError(t, err)

	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{
			{
				NewKeyName: keyName,
				Data:       importData,
				Password:   keystorePassword,
			},
		},
	})
	require.NoError(t, err)

	// Verify the key exists and has correct public key
	keysResp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	require.NoError(t, err)
	require.Len(t, keysResp.Keys, 1)

	expectedPubKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	require.Equal(t, expectedPubKey, keysResp.Keys[0].KeyInfo.PublicKey)
}

func TestProvisionKeystoreKey_IdempotentImport(t *testing.T) {
	// Test that importing the same key twice works (key already exists case)

	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	privateKeyBytes := crypto.FromECDSA(privateKey)
	keyName := "test-key"
	keystorePassword := "test-password"

	ctx := context.Background()
	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, keystorePassword)
	require.NoError(t, err)

	// Import the key first time
	importData, err := createImportData(keyName, privateKeyBytes, keystorePassword)
	require.NoError(t, err)

	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{
			{
				NewKeyName: keyName,
				Data:       importData,
				Password:   keystorePassword,
			},
		},
	})
	require.NoError(t, err)

	// Check if key exists (simulating the idempotency check in ProvisionKeystoreKey)
	keysResp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	require.NoError(t, err)
	require.Len(t, keysResp.Keys, 1, "key should exist after first import")

	// Attempting to import again should fail with key already exists
	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{
			{
				NewKeyName: keyName,
				Data:       importData,
				Password:   keystorePassword,
			},
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}
