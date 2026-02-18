package bootstrap

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

// errNoRows is a wrapped sql.ErrNoRows to verify errors.Is traversal.
var errNoRows = fmt.Errorf("query failed: %w", sql.ErrNoRows)

func TestGetJDPublicKey(t *testing.T) {
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
			wantErr: "failed to decode JD public key",
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
			got, err := getJDPublicKey(tt.input)
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

		signer, err := newCSASigner(ctx, ks, "csa-key")
		require.NoError(t, err)

		pub, ok := signer.Public().(ed25519.PublicKey)
		require.True(t, ok)
		assert.Len(t, pub, ed25519.PublicKeySize)
	})

	t.Run("key not found", func(t *testing.T) {
		t.Parallel()
		ks := newTestKeystore(t)

		_, err := newCSASigner(ctx, ks, "nonexistent")
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

		_, err = newCSASigner(ctx, ks, "ecdsa-key")
		require.ErrorContains(t, err, "not an ed25519 public key")
	})
}

func TestCSASigner_Sign(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ks := newTestKeystore(t)
	createEd25519Key(t, ks, "sign-key")

	signer, err := newCSASigner(ctx, ks, "sign-key")
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

	signer, err := newCSASigner(ctx, ks, "pub-key")
	require.NoError(t, err)

	pub1 := signer.Public()
	pub2 := signer.Public()
	assert.Equal(t, pub1, pub2, "Public must return the same key on repeated calls")
}

func TestRunner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("delegates start", func(t *testing.T) {
		t.Parallel()
		var started bool
		fac := &spyServiceFactory{
			startFn: func(_ context.Context, spec string, _ ServiceDeps) error {
				started = true
				assert.Equal(t, "my-spec", spec)
				return nil
			},
		}
		r := &runner{fac: fac, deps: ServiceDeps{}}

		err := r.StartJob(ctx, "my-spec")
		require.NoError(t, err)
		assert.True(t, started)
	})

	t.Run("delegates stop", func(t *testing.T) {
		t.Parallel()
		var stopped bool
		fac := &spyServiceFactory{
			stopFn: func(context.Context) error {
				stopped = true
				return nil
			},
		}
		r := &runner{fac: fac, deps: ServiceDeps{}}

		err := r.StopJob(ctx)
		require.NoError(t, err)
		assert.True(t, stopped)
	})

	t.Run("propagates start error", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactory{
			startFn: func(context.Context, string, ServiceDeps) error {
				return errors.New("boom")
			},
		}
		r := &runner{fac: fac, deps: ServiceDeps{}}

		err := r.StartJob(ctx, "spec")
		require.EqualError(t, err, "boom")
	})

	t.Run("propagates stop error", func(t *testing.T) {
		t.Parallel()
		fac := &spyServiceFactory{
			stopFn: func(context.Context) error {
				return errors.New("stop failed")
			},
		}
		r := &runner{fac: fac, deps: ServiceDeps{}}

		err := r.StopJob(ctx)
		require.EqualError(t, err, "stop failed")
	})
}

func TestPGStorageWrapper_GetEncryptedKeystore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("returns data from inner", func(t *testing.T) {
		t.Parallel()
		want := []byte("encrypted-blob")
		w := &pgStorageWrapper{inner: &fakeStorage{data: want}}

		got, err := w.GetEncryptedKeystore(ctx)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("converts ErrNoRows to nil", func(t *testing.T) {
		t.Parallel()

		w := &pgStorageWrapper{inner: &fakeStorage{err: errNoRows}}

		got, err := w.GetEncryptedKeystore(ctx)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("propagates other errors", func(t *testing.T) {
		t.Parallel()
		w := &pgStorageWrapper{inner: &fakeStorage{err: errors.New("disk error")}}

		_, err := w.GetEncryptedKeystore(ctx)
		require.EqualError(t, err, "disk error")
	})
}

func TestPGStorageWrapper_PutEncryptedKeystore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("delegates to inner", func(t *testing.T) {
		t.Parallel()
		s := &fakeStorage{}
		w := &pgStorageWrapper{inner: s}

		err := w.PutEncryptedKeystore(ctx, []byte("data"))
		require.NoError(t, err)
		assert.Equal(t, []byte("data"), s.data)
	})

	t.Run("propagates error", func(t *testing.T) {
		t.Parallel()
		s := &fakeStorage{err: errors.New("write failed")}
		w := &pgStorageWrapper{inner: s}

		err := w.PutEncryptedKeystore(ctx, []byte("data"))
		require.EqualError(t, err, "write failed")
	})
}

// --- test helpers ---

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

// spyServiceFactory records calls to Start and Stop.
type spyServiceFactory struct {
	startFn func(context.Context, string, ServiceDeps) error
	stopFn  func(context.Context) error
}

func (s *spyServiceFactory) Start(ctx context.Context, spec string, deps ServiceDeps) error {
	if s.startFn != nil {
		return s.startFn(ctx, spec, deps)
	}
	return nil
}

func (s *spyServiceFactory) Stop(ctx context.Context) error {
	if s.stopFn != nil {
		return s.stopFn(ctx)
	}
	return nil
}

// fakeStorage is an in-memory [keystore.Storage] for testing pgStorageWrapper.
type fakeStorage struct {
	data []byte
	err  error
}

func (f *fakeStorage) GetEncryptedKeystore(context.Context) ([]byte, error) {
	return f.data, f.err
}

func (f *fakeStorage) PutEncryptedKeystore(_ context.Context, data []byte) error {
	if f.err != nil {
		return f.err
	}
	f.data = data
	return nil
}
