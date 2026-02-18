package keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

// newTestKeystore creates an empty in-memory keystore for testing.
func newTestKeystore(t *testing.T) keystore.Keystore {
	t.Helper()
	ks, err := keystore.LoadKeystore(
		context.Background(),
		keystore.NewMemoryStorage(),
		"test-password",
		keystore.WithScryptParams(keystore.FastScryptParams),
	)
	require.NoError(t, err)
	return ks
}

// createEd25519Key creates an Ed25519 key in the keystore for testing.
func createEd25519Key(t *testing.T, ks keystore.Keystore, name string) {
	t.Helper()
	_, err := ks.CreateKeys(context.Background(), keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{
			{KeyName: name, KeyType: keystore.Ed25519},
		},
	})
	require.NoError(t, err)
}
