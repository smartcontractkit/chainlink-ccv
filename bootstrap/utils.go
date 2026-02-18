package bootstrap

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/pgstore"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// A runner adapts a [ServiceFactory] to the [lifecycle.JobRunner] interface.
type runner struct {
	fac  ServiceFactory
	deps ServiceDeps
}

var _ lifecycle.JobRunner = (*runner)(nil)

// StartJob implements [lifecycle.JobRunner] and delegates to the services Start method.
func (r *runner) StartJob(ctx context.Context, spec string) error {
	return r.fac.Start(ctx, spec, r.deps)
}

// StopJob implements [lifecycle.JobRunner] and delegates to the services Stop method.
func (r *runner) StopJob(ctx context.Context) error {
	return r.fac.Stop(ctx)
}

// getJDPublicKey decodes a hex-encoded (CSA) Ed25519 public key.
func getJDPublicKey(pubKey string) (ed25519.PublicKey, error) {
	decoded, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JD public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"JD public key is not an ed25519 public key: expected %d bytes, got %d bytes",
			ed25519.PublicKeySize,
			len(decoded),
		)
	}
	return ed25519.PublicKey(decoded), nil
}

// A csaSigner implements [crypto.Signer] using a keystore-managed Ed25519 key.
type csaSigner struct {
	ks        keystore.Keystore
	keyName   string
	publicKey crypto.PublicKey
}

var _ crypto.Signer = (*csaSigner)(nil)

// newCSASigner returns a [crypto.Signer] for the named Ed25519 key in ks.
func newCSASigner(ctx context.Context, ks keystore.Keystore, keyName string) (*csaSigner, error) {
	resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{
		KeyNames: []string{keyName},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	if len(resp.Keys) == 0 {
		return nil, fmt.Errorf("key %q not found", keyName)
	}
	if len(resp.Keys) != 1 {
		return nil, fmt.Errorf("expected 1 key, got %d", len(resp.Keys))
	}
	publicKey := resp.Keys[0].KeyInfo.PublicKey
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is not an ed25519 public key")
	}
	return &csaSigner{
		ks:        ks,
		keyName:   keyName,
		publicKey: ed25519.PublicKey(publicKey),
	}, nil
}

// Public returns the public key.
func (s *csaSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the keystore-managed private key.
func (s *csaSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	resp, err := s.ks.Sign(context.TODO(), keystore.SignRequest{
		KeyName: s.keyName,
		Data:    digest,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return resp.Signature, nil
}

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
