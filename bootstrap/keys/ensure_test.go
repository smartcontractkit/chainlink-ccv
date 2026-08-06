package keys

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestEnsureKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lggr := logger.TestSugared(t)

	t.Run("creates key when not present", func(t *testing.T) {
		t.Parallel()
		ks := newTestKeystore(t)

		err := EnsureKey(ctx, lggr, ks, "my-ecdsa-key", "signing", keystore.ECDSA_S256)
		require.NoError(t, err)

		resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"my-ecdsa-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		assert.Equal(t, keystore.ECDSA_S256, resp.Keys[0].KeyInfo.KeyType)
	})

	t.Run("reuses existing key", func(t *testing.T) {
		t.Parallel()
		ks := newTestKeystore(t)
		createResp, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{{KeyName: "existing-key", KeyType: keystore.Ed25519}},
		})
		require.NoError(t, err)
		wantPub := createResp.Keys[0].KeyInfo.PublicKey

		err = EnsureKey(ctx, lggr, ks, "existing-key", "signing", keystore.Ed25519)
		require.NoError(t, err)

		resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"existing-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		assert.Equal(t, wantPub, resp.Keys[0].KeyInfo.PublicKey)
	})

	t.Run("creates multiple key types", func(t *testing.T) {
		t.Parallel()
		ks := newTestKeystore(t)

		require.NoError(t, EnsureKey(ctx, lggr, ks, "ecdsa-key", "signing", keystore.ECDSA_S256))
		require.NoError(t, EnsureKey(ctx, lggr, ks, "ed25519-key", "signing", keystore.Ed25519))

		resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"ecdsa-key", "ed25519-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 2)

		got := make(map[string]keystore.KeyType)
		for _, k := range resp.Keys {
			got[k.KeyInfo.Name] = k.KeyInfo.KeyType
		}
		assert.Equal(t, keystore.ECDSA_S256, got["ecdsa-key"])
		assert.Equal(t, keystore.Ed25519, got["ed25519-key"])
	})
}

// The executor's generated transmitter has to be funded before it can transmit, and the address is
// what gets funded, so a secp256k1 key logs the derived address alongside the public key. An
// operator reads it off the startup log rather than deriving a keccak hash by hand.
func TestKeyLogFieldsIncludesTheEVMAddressForSecp256k1Keys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lggr := logger.TestSugared(t)
	ks := newTestKeystore(t)

	createResp, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{{KeyName: "transmitter", KeyType: keystore.ECDSA_S256}},
	})
	require.NoError(t, err)
	publicKey := createResp.Keys[0].KeyInfo.PublicKey

	fields := keyLogFields(lggr, "transmitter", "transmitting", keystore.ECDSA_S256, publicKey)
	wantAddress, _, err := EVMAddressFromPublicKey(publicKey)
	require.NoError(t, err)
	assert.Equal(t, wantAddress, fieldValue(t, fields, "evmAddress"),
		"the address an operator funds must be in the log, checksummed as EVMAddressFromPublicKey returns it")
}

// Ed25519 keys have no EVM address, so the field is absent rather than empty or wrong.
func TestKeyLogFieldsOmitsTheEVMAddressForOtherKeyTypes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lggr := logger.TestSugared(t)
	ks := newTestKeystore(t)

	createResp, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{{KeyName: "csa", KeyType: keystore.Ed25519}},
	})
	require.NoError(t, err)

	fields := keyLogFields(lggr, "csa", "JD authentication", keystore.Ed25519, createResp.Keys[0].KeyInfo.PublicKey)
	assert.NotContains(t, fields, "evmAddress")
}

// A secp256k1 public key the geth decoder rejects must not fail the boot: the keystore holds a
// usable key, and only the address field is unavailable.
func TestKeyLogFieldsToleratesAnUndecodablePublicKey(t *testing.T) {
	t.Parallel()
	lggr := logger.TestSugared(t)

	fields := keyLogFields(lggr, "transmitter", "transmitting", keystore.ECDSA_S256, []byte{0x01, 0x02})
	assert.NotContains(t, fields, "evmAddress")
	assert.Equal(t, "0102", fieldValue(t, fields, "publicKey"))
}

// fieldValue reads the value following key in a flat list of logger key/value pairs.
func fieldValue(t *testing.T, fields []any, key string) any {
	t.Helper()
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	t.Fatalf("log fields %v carry no %q", fields, key)
	return nil
}

func TestIsKeyNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "exact sentinel",
			err:  keystore.ErrKeyNotFound,
			want: true,
		},
		{
			name: "wrapped sentinel",
			err:  fmt.Errorf("get failed: %w", keystore.ErrKeyNotFound),
			want: true,
		},
		{
			name: "string match without wrapping",
			err:  fmt.Errorf("key not found: my-key"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("connection refused"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isKeyNotFound(tt.err))
		})
	}
}
