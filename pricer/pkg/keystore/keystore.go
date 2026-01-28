package keystore

import (
	"context"
	"fmt"

	ks "github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/kms"
)

// KMSConfig provides global KMS configuration for the pricer service.
// Global as we imagine key re-use across chains.
type KMSConfig struct {
	Profile      string `toml:"profile"`
	EcdsaKeyID   string `toml:"ecdsa_key_id"`
	Ed25519KeyID string `toml:"ed25519_key_id"`
}

func LoadKMSKeystore(ctx context.Context, profile string) (interface {
	ks.Reader
	ks.Signer
}, error,
) {
	kmsClient, err := kms.NewClient(ctx, kms.ClientOptions{
		Profile: profile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}
	return kms.NewKeystore(kmsClient)
}

func LoadMemoryKeystore(ctx context.Context, keystoreData []byte, keystorePassword string) (interface {
	ks.Reader
	ks.Signer
}, error,
) {
	memStorage := ks.NewMemoryStorage()
	if err := memStorage.PutEncryptedKeystore(ctx, keystoreData); err != nil {
		return nil, fmt.Errorf("failed to populate keystore storage: %w", err)
	}
	return ks.LoadKeystore(ctx, memStorage, keystorePassword, ks.WithScryptParams(ks.FastScryptParams))
}
