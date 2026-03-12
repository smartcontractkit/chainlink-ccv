package keys

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

// DecodeEd25519PublicKey decodes a hex-encoded Ed25519 public key.
func DecodeEd25519PublicKey(pubKeyHex string) (ed25519.PublicKey, error) {
	decoded, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"not an ed25519 public key: expected %d bytes, got %d bytes",
			ed25519.PublicKeySize,
			len(decoded),
		)
	}
	return ed25519.PublicKey(decoded), nil
}

// A CSASigner implements [crypto.Signer] using a keystore-managed Ed25519 key.
type CSASigner struct {
	ks        keystore.Keystore
	keyName   string
	publicKey crypto.PublicKey
}

var _ crypto.Signer = (*CSASigner)(nil)

// NewCSASigner returns a [crypto.Signer] for the named Ed25519 key in ks.
func NewCSASigner(ctx context.Context, ks keystore.Keystore, keyName string) (*CSASigner, error) {
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
	return &CSASigner{
		ks:        ks,
		keyName:   keyName,
		publicKey: ed25519.PublicKey(publicKey),
	}, nil
}

// Public returns the public key.
func (s *CSASigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the keystore-managed private key.
func (s *CSASigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	resp, err := s.ks.Sign(context.TODO(), keystore.SignRequest{
		KeyName: s.keyName,
		Data:    digest,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return resp.Signature, nil
}
