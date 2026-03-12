package keys

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

func TestDecodeEd25519PublicKey(t *testing.T) {
	t.Parallel()

	validKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	validHex := hex.EncodeToString(validKey.Public().(ed25519.PublicKey))

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:  "valid key",
			input: validHex,
		},
		{
			name:    "invalid hex",
			input:   "zzzz",
			wantErr: "failed to decode public key",
		},
		{
			name:    "wrong length",
			input:   "abcdef",
			wantErr: "not an ed25519 public key",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: "not an ed25519 public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeEd25519PublicKey(tt.input)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, got, ed25519.PublicKeySize)
		})
	}
}

func TestNewCSASigner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("valid ed25519 key", func(t *testing.T) {
		t.Parallel()
		ks := newTestKeystore(t)
		createEd25519Key(t, ks, "csa-key")

		signer, err := NewCSASigner(ctx, ks, "csa-key")
		require.NoError(t, err)

		pub, ok := signer.Public().(ed25519.PublicKey)
		require.True(t, ok)
		assert.Len(t, pub, ed25519.PublicKeySize)
	})

	t.Run("key not found", func(t *testing.T) {
		t.Parallel()
		ks := newTestKeystore(t)

		_, err := NewCSASigner(ctx, ks, "nonexistent")
		require.ErrorContains(t, err, "nonexistent")
	})

	t.Run("wrong key type", func(t *testing.T) {
		t.Parallel()
		ks := newTestKeystore(t)
		_, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{
				{KeyName: "ecdsa-key", KeyType: keystore.ECDSA_S256},
			},
		})
		require.NoError(t, err)

		_, err = NewCSASigner(ctx, ks, "ecdsa-key")
		require.ErrorContains(t, err, "not an ed25519 public key")
	})
}

func TestCSASigner_Sign(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ks := newTestKeystore(t)
	createEd25519Key(t, ks, "sign-key")

	signer, err := NewCSASigner(ctx, ks, "sign-key")
	require.NoError(t, err)

	digest := []byte("test message")
	sig, err := signer.Sign(nil, digest, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	pub := signer.Public().(ed25519.PublicKey)
	assert.True(t, ed25519.Verify(pub, digest, sig))
}

func TestCSASigner_Public(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ks := newTestKeystore(t)
	createEd25519Key(t, ks, "pub-key")

	signer, err := NewCSASigner(ctx, ks, "pub-key")
	require.NoError(t, err)

	pub1 := signer.Public()
	pub2 := signer.Public()
	assert.Equal(t, pub1, pub2, "Public must return the same key on repeated calls")
}
