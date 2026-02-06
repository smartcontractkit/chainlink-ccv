// Package keys provides key management utilities for the verifier.
package keys

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"io"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	ks "github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/pgstore"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

const (
	// SigningKeyName is the default name for the signing key (ECDSA_S256).
	SigningKeyName = "verifier/signing/default"
	// CSAKeyName is the default name for the CSA key (Ed25519).
	CSAKeyName = "verifier/csa/default"
)

// NewPGStorage creates a keystore storage that handles the case where no keystore
// exists yet (returns empty data instead of sql.ErrNoRows).
func NewPGStorage(ds sqlutil.DataSource, name string) ks.Storage {
	return &pgStorageWrapper{inner: pgstore.NewStorage(ds, name)}
}

// pgStorageWrapper wraps pgstore.Storage to handle sql.ErrNoRows gracefully.
// The keystore library expects GetEncryptedKeystore to return (nil, nil) or ([]byte{}, nil)
// when no data exists, but pgstore returns (nil, sql.ErrNoRows).
type pgStorageWrapper struct {
	inner *pgstore.Storage
}

func (w *pgStorageWrapper) GetEncryptedKeystore(ctx context.Context) ([]byte, error) {
	data, err := w.inner.GetEncryptedKeystore(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		// No keystore exists yet - return empty data so LoadKeystore creates an empty keystore
		return nil, nil
	}
	return data, err
}

func (w *pgStorageWrapper) PutEncryptedKeystore(ctx context.Context, encryptedKeystore []byte) error {
	return w.inner.PutEncryptedKeystore(ctx, encryptedKeystore)
}

// KeyPair holds both the signing key and CSA key information.
type KeyPair struct {
	// SigningAddress is the Ethereum address derived from the signing key.
	SigningAddress string
	// CSAPublicKey is the Ed25519 public key for JD authentication.
	CSAPublicKey ed25519.PublicKey
	// CSASigner implements crypto.Signer for the CSA key, used for WSRPC authentication.
	// The private key never leaves the keystore.
	CSASigner crypto.Signer
}

// CSAKeystoreSigner implements crypto.Signer using the keystore.
// This allows signing without exposing the raw private key.
type CSAKeystoreSigner struct {
	keystore  ks.Signer
	keyName   string
	publicKey ed25519.PublicKey
}

// Public returns the public key corresponding to the private key.
func (s *CSAKeystoreSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key. For Ed25519, the digest is the message itself
// (not a hash), and opts should be crypto.Hash(0).
func (s *CSAKeystoreSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Ed25519 signs the message directly, not a hash
	resp, err := s.keystore.Sign(context.Background(), ks.SignRequest{
		KeyName: s.keyName,
		Data:    digest,
	})
	if err != nil {
		return nil, fmt.Errorf("keystore sign failed: %w", err)
	}
	return resp.Signature, nil
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
	csaSigner, csaPub, err := getOrCreateCSAKey(ctx, keystore)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create CSA key: %w", err)
	}

	return &KeyPair{
		SigningAddress: signingAddr,
		CSAPublicKey:   csaPub,
		CSASigner:      csaSigner,
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

// getOrCreateCSAKey ensures the CSA key exists and returns a crypto.Signer and public key.
// The private key stays in the keystore and is never exposed.
func getOrCreateCSAKey(ctx context.Context, keystore ks.Keystore) (crypto.Signer, ed25519.PublicKey, error) {
	// Check if key exists by getting all keys and filtering
	allKeysResp, err := keystore.GetKeys(ctx, ks.GetKeysRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Look for existing CSA key
	var csaPublicKey ed25519.PublicKey
	for _, key := range allKeysResp.Keys {
		if key.KeyInfo.Name == CSAKeyName {
			csaPublicKey = key.KeyInfo.PublicKey
			break
		}
	}

	if csaPublicKey == nil {
		// Create the key
		createResp, err := keystore.CreateKeys(ctx, ks.CreateKeysRequest{
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
		if len(createResp.Keys) == 0 {
			return nil, nil, fmt.Errorf("no key returned after creation")
		}
		csaPublicKey = createResp.Keys[0].KeyInfo.PublicKey
	}

	// Create a crypto.Signer that delegates to the keystore
	signer := &CSAKeystoreSigner{
		keystore:  keystore,
		keyName:   CSAKeyName,
		publicKey: csaPublicKey,
	}

	return signer, csaPublicKey, nil
}

// deriveAddressFromPublicKey derives an Ethereum address from a SEC1 uncompressed public key.
func deriveAddressFromPublicKey(publicKey []byte) (string, error) {
	if len(publicKey) != 65 {
		return "", fmt.Errorf("unexpected public key length %d, expected 65", len(publicKey))
	}

	pubKey, err := gethcrypto.UnmarshalPubkey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	address := gethcrypto.PubkeyToAddress(*pubKey)
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
