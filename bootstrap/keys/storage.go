package keys

import (
	"context"
	"database/sql"
	"errors"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/pgstore"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// NewPGStorage returns a [keystore.Storage] backed by PostgreSQL.
// It wraps [pgstore.Storage] to convert [sql.ErrNoRows] into (nil, nil),
// which [keystore.LoadKeystore] requires when no keystore exists yet.
func NewPGStorage(ds sqlutil.DataSource, name string) keystore.Storage {
	return &pgStorageWrapper{inner: pgstore.NewStorage(ds, name)}
}

// A pgStorageWrapper converts [sql.ErrNoRows] from the inner [keystore.Storage] into nil.
type pgStorageWrapper struct {
	inner keystore.Storage
}

var _ keystore.Storage = (*pgStorageWrapper)(nil)

// GetEncryptedKeystore returns the encrypted keystore, or (nil, nil) if none exists.
func (w *pgStorageWrapper) GetEncryptedKeystore(ctx context.Context) ([]byte, error) {
	data, err := w.inner.GetEncryptedKeystore(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return data, err
}

// PutEncryptedKeystore writes the encrypted keystore.
func (w *pgStorageWrapper) PutEncryptedKeystore(ctx context.Context, encryptedKeystore []byte) error {
	return w.inner.PutEncryptedKeystore(ctx, encryptedKeystore)
}
