package util

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/jmoiron/sqlx"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/pgstore"
	"github.com/smartcontractkit/chainlink-common/keystore/serialization"
)

// createImportData creates keystore-compatible encrypted import data from raw private key bytes.
// This allows importing deterministic test keys into the keystore.
func createImportData(keyName string, privateKeyBytes []byte, password string) ([]byte, error) {
	keypb := &serialization.Key{
		Name:       keyName,
		KeyType:    string(keystore.ECDSA_S256),
		PrivateKey: privateKeyBytes,
		CreatedAt:  time.Now().Unix(),
		Metadata:   []byte{},
	}

	serialized, err := proto.Marshal(keypb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	// Encrypt using geth keystore encryption (same as keystore library uses)
	encData, err := gethkeystore.EncryptDataV3(serialized, []byte(password), keystore.DefaultScryptParams.N, keystore.DefaultScryptParams.P)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key data: %w", err)
	}

	encDataBytes, err := json.Marshal(encData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted data: %w", err)
	}

	return encDataBytes, nil
}

const (
	// DefaultKeystoreName is the name used for keystore storage in the database.
	DefaultKeystoreName = "verifier-keystore"
	// DefaultKeystoreKeyName is the name for the signing key within the keystore.
	DefaultKeystoreKeyName = "verifier-signing-key"
	// DefaultKeystorePassword is a devenv-only password for the keystore.
	// In production, this should be provided via secure configuration.
	DefaultKeystorePassword = "devenv-keystore-password-not-for-production"
)

// ProvisionKeystoreKey provisions a signing key in the keystore database.
// It connects to the database, creates the keystore table if needed,
// and imports the provided private key.
//
// Parameters:
//   - dbURL: PostgreSQL connection string (e.g., "postgresql://user:pass@host:port/db?sslmode=disable")
//   - keystoreName: Name for the keystore storage (e.g., "verifier-keystore")
//   - keyName: Name for the key within the keystore (e.g., "verifier-signing-key")
//   - privateKeyBytes: Raw 32-byte ECDSA private key
//   - keystorePassword: Password to encrypt the keystore
//
// Returns the public key bytes (65 bytes, SEC1 uncompressed format) and any error.
func ProvisionKeystoreKey(
	ctx context.Context,
	dbURL string,
	keystoreName string,
	keyName string,
	privateKeyBytes []byte,
	keystorePassword string,
) ([]byte, error) {
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privateKeyBytes))
	}

	// Connect to the database
	db, err := sqlx.ConnectContext(ctx, "postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Create the keystore storage
	storage := pgstore.NewStorage(db, keystoreName)

	// Load (or create) the keystore
	ks, err := keystore.LoadKeystore(ctx, storage, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}

	// Check if key already exists
	existingKeys, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	if err == nil && len(existingKeys.Keys) > 0 {
		// Key already exists, return its public key
		return existingKeys.Keys[0].KeyInfo.PublicKey, nil
	}

	// Create import-compatible encrypted data from raw private key bytes
	importData, err := createImportData(keyName, privateKeyBytes, keystorePassword)
	if err != nil {
		return nil, fmt.Errorf("failed to create import data: %w", err)
	}

	// Import the key
	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{
			{
				NewKeyName: keyName,
				Data:       importData,
				Password:   keystorePassword,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	// Retrieve and return the public key
	keys, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	if err != nil {
		return nil, fmt.Errorf("failed to get imported key: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("imported key not found")
	}

	return keys.Keys[0].KeyInfo.PublicKey, nil
}
