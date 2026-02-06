// Package keys provides key management utilities for the verifier.
package keys

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/protobuf/proto"

	ks "github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/serialization"
)

const (
	// SigningKeyName is the default name for the signing key (ECDSA_S256).
	SigningKeyName = "verifier/signing/default"
	// CSAKeyName is the default name for the CSA key (Ed25519).
	CSAKeyName = "verifier/csa/default"

	// tempExportPassword is used internally for key extraction.
	tempExportPassword = "temp-extract-password-0xdeadbeef"
)

// KeyPair holds both the signing key and CSA key information.
type KeyPair struct {
	// SigningAddress is the Ethereum address derived from the signing key.
	SigningAddress string
	// CSAPublicKey is the Ed25519 public key for JD authentication.
	CSAPublicKey ed25519.PublicKey
	// CSAPrivateKey is the Ed25519 private key for JD authentication.
	CSAPrivateKey ed25519.PrivateKey
}

// GetOrCreateKeys ensures both signing and CSA keys exist in the keystore,
// creating them if necessary. Returns the key information needed for the verifier.
func GetOrCreateKeys(ctx context.Context, keystore ks.Keystore) (*KeyPair, error) {
	// Get or create signing key (ECDSA_S256)
	signingAddr, err := getOrCreateSigningKey(ctx, keystore)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create signing key: %w", err)
	}

	// Get or create CSA key (Ed25519)
	csaPriv, csaPub, err := getOrCreateCSAKey(ctx, keystore)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create CSA key: %w", err)
	}

	return &KeyPair{
		SigningAddress: signingAddr,
		CSAPublicKey:   csaPub,
		CSAPrivateKey:  csaPriv,
	}, nil
}

// getOrCreateSigningKey ensures the signing key exists and returns its Ethereum address.
func getOrCreateSigningKey(ctx context.Context, keystore ks.Keystore) (string, error) {
	// Check if key exists by getting all keys and filtering
	allKeysResp, err := keystore.GetKeys(ctx, ks.GetKeysRequest{})
	if err != nil {
		return "", fmt.Errorf("failed to list keys: %w", err)
	}

	// Look for existing signing key
	for _, key := range allKeysResp.Keys {
		if key.KeyInfo.Name == SigningKeyName {
			return deriveAddressFromPublicKey(key.KeyInfo.PublicKey)
		}
	}

	// Key doesn't exist, create it
	createResp, err := keystore.CreateKeys(ctx, ks.CreateKeysRequest{
		Keys: []ks.CreateKeyRequest{
			{
				KeyName: SigningKeyName,
				KeyType: ks.ECDSA_S256,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create signing key: %w", err)
	}
	if len(createResp.Keys) == 0 {
		return "", fmt.Errorf("no key returned after creation")
	}

	// Derive address from the public key
	return deriveAddressFromPublicKey(createResp.Keys[0].KeyInfo.PublicKey)
}

// getOrCreateCSAKey ensures the CSA key exists and returns its key pair.
func getOrCreateCSAKey(ctx context.Context, keystore ks.Keystore) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	// Check if key exists by getting all keys and filtering
	allKeysResp, err := keystore.GetKeys(ctx, ks.GetKeysRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Look for existing CSA key
	keyExists := false
	for _, key := range allKeysResp.Keys {
		if key.KeyInfo.Name == CSAKeyName {
			keyExists = true
			break
		}
	}

	if !keyExists {
		// Create the key
		_, err := keystore.CreateKeys(ctx, ks.CreateKeysRequest{
			Keys: []ks.CreateKeyRequest{
				{
					KeyName: CSAKeyName,
					KeyType: ks.Ed25519,
				},
			},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create CSA key: %w", err)
		}
	}

	// Extract the private key for WSRPC authentication
	return extractCSAPrivateKey(ctx, keystore)
}

// extractCSAPrivateKey extracts the raw Ed25519 private key from the keystore.
// This is needed for WSRPC which requires the actual private key bytes.
func extractCSAPrivateKey(ctx context.Context, store ks.Keystore) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	// Export the key with a temporary password
	exportResp, err := store.ExportKeys(ctx, ks.ExportKeysRequest{
		Keys: []ks.ExportKeyParam{
			{
				KeyName: CSAKeyName,
				Enc: ks.EncryptionParams{
					Password:     tempExportPassword,
					ScryptParams: ks.FastScryptParams,
				},
			},
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to export CSA key: %w", err)
	}
	if len(exportResp.Keys) == 0 {
		return nil, nil, fmt.Errorf("no key returned from export")
	}

	// The exported data is encrypted using geth's keystore format.
	// Decrypt it to get the raw private key bytes.
	var encryptedData keystore.CryptoJSON
	if err := json.Unmarshal(exportResp.Keys[0].Data, &encryptedData); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal encrypted key data: %w", err)
	}

	decryptedData, err := keystore.DecryptDataV3(encryptedData, tempExportPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt key data: %w", err)
	}

	// Unmarshal the protobuf key structure
	var key serialization.Key
	if err := proto.Unmarshal(decryptedData, &key); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal key protobuf: %w", err)
	}

	// Validate the key type
	if key.KeyType != string(ks.Ed25519) {
		return nil, nil, fmt.Errorf("unexpected key type %s, expected %s", key.KeyType, ks.Ed25519)
	}

	// Ed25519 private keys should be 64 bytes
	if len(key.PrivateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("unexpected private key size %d, expected %d", len(key.PrivateKey), ed25519.PrivateKeySize)
	}

	privateKey := ed25519.PrivateKey(key.PrivateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return privateKey, publicKey, nil
}

// deriveAddressFromPublicKey derives an Ethereum address from a SEC1 uncompressed public key.
func deriveAddressFromPublicKey(publicKey []byte) (string, error) {
	if len(publicKey) != 65 {
		return "", fmt.Errorf("unexpected public key length %d, expected 65", len(publicKey))
	}

	pubKey, err := crypto.UnmarshalPubkey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	address := crypto.PubkeyToAddress(*pubKey)
	return address.Hex(), nil
}

// GetSigningAddress retrieves the signing address from an existing keystore.
// Returns an error if the key doesn't exist.
func GetSigningAddress(ctx context.Context, keystore ks.Keystore) (string, error) {
	keysResp, err := keystore.GetKeys(ctx, ks.GetKeysRequest{KeyNames: []string{SigningKeyName}})
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}
	if len(keysResp.Keys) == 0 {
		return "", fmt.Errorf("signing key %q not found", SigningKeyName)
	}
	return deriveAddressFromPublicKey(keysResp.Keys[0].KeyInfo.PublicKey)
}

// GetCSAPublicKey retrieves the CSA public key from an existing keystore.
// Returns an error if the key doesn't exist.
func GetCSAPublicKey(ctx context.Context, keystore ks.Keystore) (ed25519.PublicKey, error) {
	keysResp, err := keystore.GetKeys(ctx, ks.GetKeysRequest{KeyNames: []string{CSAKeyName}})
	if err != nil {
		return nil, fmt.Errorf("failed to get CSA key: %w", err)
	}
	if len(keysResp.Keys) == 0 {
		return nil, fmt.Errorf("CSA key %q not found", CSAKeyName)
	}
	return keysResp.Keys[0].KeyInfo.PublicKey, nil
}
