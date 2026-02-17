package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// newTestKeystore creates an empty in-memory keystore for testing.
func newTestKeystore(t *testing.T) keystore.Keystore {
	t.Helper()
	ctx := context.Background()
	storage := keystore.NewMemoryStorage()
	ks, err := keystore.LoadKeystore(ctx, storage, "test-password", keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)
	return ks
}

func Test_ensureKey(t *testing.T) {
	ctx := context.Background()
	lggr := logger.TestSugared(t)

	t.Run("creates key when not present", func(t *testing.T) {
		keyStore := newTestKeystore(t)
		err := ensureKey(ctx, lggr, keyStore, "my-ecdsa-key", "signing", keystore.ECDSA_S256)
		require.NoError(t, err)

		resp, err := keyStore.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"my-ecdsa-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		require.Equal(t, keystore.ECDSA_S256, resp.Keys[0].KeyInfo.KeyType)
	})

	t.Run("reuses key when already present", func(t *testing.T) {
		keyStore := newTestKeystore(t)
		// Create key first
		createResp, err := keyStore.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{
				{KeyName: "existing-key", KeyType: keystore.Ed25519},
			},
		})
		require.NoError(t, err)
		require.Len(t, createResp.Keys, 1)
		existingPublicKey := createResp.Keys[0].KeyInfo.PublicKey

		err = ensureKey(ctx, lggr, keyStore, "existing-key", "signing", keystore.Ed25519)
		require.NoError(t, err)

		resp, err := keyStore.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"existing-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		require.Equal(t, existingPublicKey, resp.Keys[0].KeyInfo.PublicKey, "should return same key, not create duplicate")
	})

	t.Run("creates ECDSA and Ed25519 keys with correct types", func(t *testing.T) {
		keyStore := newTestKeystore(t)

		err := ensureKey(ctx, lggr, keyStore, "ecdsa-key", "signing", keystore.ECDSA_S256)
		require.NoError(t, err)
		err = ensureKey(ctx, lggr, keyStore, "ed25519-key", "signing", keystore.Ed25519)
		require.NoError(t, err)

		resp, err := keyStore.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"ecdsa-key", "ed25519-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 2)
		keyTypes := make(map[string]keystore.KeyType)
		for _, k := range resp.Keys {
			keyTypes[k.KeyInfo.Name] = k.KeyInfo.KeyType
		}
		require.Equal(t, keystore.ECDSA_S256, keyTypes["ecdsa-key"])
		require.Equal(t, keystore.Ed25519, keyTypes["ed25519-key"])
	})
}

func Test_ensureAllSigningKeys(t *testing.T) {
	ctx := context.Background()
	lggr := logger.TestSugared(t)

	t.Run("creates both ECDSA and EdDSA keys in empty keystore", func(t *testing.T) {
		keyStore := newTestKeystore(t)

		err := ensureAllSigningKeys(ctx, lggr, keyStore)
		require.NoError(t, err)

		resp, err := keyStore.GetKeys(ctx, keystore.GetKeysRequest{
			KeyNames: []string{DefaultECDSASigningKeyName, DefaultEdDSASigningKeyName},
		})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 2)
		keyTypes := make(map[string]keystore.KeyType)
		for _, k := range resp.Keys {
			keyTypes[k.KeyInfo.Name] = k.KeyInfo.KeyType
		}
		require.Equal(t, keystore.ECDSA_S256, keyTypes[DefaultECDSASigningKeyName])
		require.Equal(t, keystore.Ed25519, keyTypes[DefaultEdDSASigningKeyName])
	})

	t.Run("idempotent when keys already exist", func(t *testing.T) {
		keyStore := newTestKeystore(t)

		err := ensureAllSigningKeys(ctx, lggr, keyStore)
		require.NoError(t, err)
		resp1, err := keyStore.GetKeys(ctx, keystore.GetKeysRequest{
			KeyNames: []string{DefaultECDSASigningKeyName, DefaultEdDSASigningKeyName},
		})
		require.NoError(t, err)
		require.Len(t, resp1.Keys, 2)
		ecdsaPub1 := resp1.Keys[0].KeyInfo.PublicKey
		eddsaPub1 := resp1.Keys[1].KeyInfo.PublicKey
		if resp1.Keys[0].KeyInfo.Name == DefaultEdDSASigningKeyName {
			ecdsaPub1, eddsaPub1 = eddsaPub1, ecdsaPub1
		}

		err = ensureAllSigningKeys(ctx, lggr, keyStore)
		require.NoError(t, err)
		resp2, err := keyStore.GetKeys(ctx, keystore.GetKeysRequest{
			KeyNames: []string{DefaultECDSASigningKeyName, DefaultEdDSASigningKeyName},
		})
		require.NoError(t, err)
		require.Len(t, resp2.Keys, 2)
		var ecdsaPub2, eddsaPub2 []byte
		for _, k := range resp2.Keys {
			if k.KeyInfo.Name == DefaultECDSASigningKeyName {
				ecdsaPub2 = k.KeyInfo.PublicKey
			} else {
				eddsaPub2 = k.KeyInfo.PublicKey
			}
		}
		require.Equal(t, ecdsaPub1, ecdsaPub2, "ECDSA key should be unchanged")
		require.Equal(t, eddsaPub1, eddsaPub2, "EdDSA key should be unchanged")
	})
}
