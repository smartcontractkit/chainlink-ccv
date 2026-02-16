package bootstrap

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/smartcontractkit/chainlink-ccv/common/jd/lifecycle"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

type runner struct {
	fac  ServiceFactory
	deps ServiceDeps
}

// StartJob implements [lifecycle.JobRunner].
func (r *runner) StartJob(ctx context.Context, spec string) error {
	return r.fac.Start(ctx, spec, r.deps)
}

// StopJob implements [lifecycle.JobRunner].
func (r *runner) StopJob(ctx context.Context) error {
	return r.fac.Stop(ctx)
}

var _ lifecycle.JobRunner = &runner{}

func getJDPublicKey(pubKey string) (ed25519.PublicKey, error) {
	jdPublicKey, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode JD public key: %w", err)
	}
	if len(jdPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("JD public key is not an ed25519 public key")
	}

	return ed25519.PublicKey(jdPublicKey), nil
}

type csaSigner struct {
	ks        keystore.Keystore
	keyName   string
	publicKey crypto.PublicKey
}

// newCSASigner creates a new csaSigner from a keystore and a key name.
func newCSASigner(ks keystore.Keystore, keyName string) (*csaSigner, error) {
	// Fetch the key w/ keyName from the keystore, and extract the public key.
	resp, err := ks.GetKeys(context.Background(), keystore.GetKeysRequest{
		KeyNames: []string{keyName},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	if len(resp.Keys) == 0 {
		return nil, fmt.Errorf("key %s not found", keyName)
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

func (s *csaSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *csaSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	resp, err := s.ks.Sign(context.Background(), keystore.SignRequest{
		KeyName: s.keyName,
		Data:    digest,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return resp.Signature, nil
}

var _ crypto.Signer = &csaSigner{}
