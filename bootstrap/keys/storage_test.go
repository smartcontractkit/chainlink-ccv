package keys

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

// errNoRows is a wrapped sql.ErrNoRows to verify errors.Is traversal.
var errNoRows = fmt.Errorf("query failed: %w", sql.ErrNoRows)

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

// fakeStorage is an in-memory [keystore.Storage] for testing pgStorageWrapper.
type fakeStorage struct {
	data []byte
	err  error
}

var _ keystore.Storage = (*fakeStorage)(nil)

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
