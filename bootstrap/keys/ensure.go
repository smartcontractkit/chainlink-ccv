package keys

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Default key names used by the bootstrapper.
const (
	DefaultECDSASigningKeyName = "bootstrap_default_ecdsa_signing_key"
	DefaultEdDSASigningKeyName = "bootstrap_default_eddsa_signing_key"
	DefaultCSAKeyName          = "bootstrap_default_csa_key"
)

// EnsureKey creates keyName in the keystore if it does not already exist.
func EnsureKey(
	ctx context.Context,
	lggr logger.Logger,
	ks keystore.Keystore,
	keyName, purpose string,
	keyType keystore.KeyType,
) error {
	resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{
		KeyNames: []string{keyName},
	})
	if err == nil && len(resp.Keys) > 0 {
		lggr.Infow("key already exists",
			"keyName", keyName, "keyType", keyType, "purpose", purpose,
			"publicKey", hex.EncodeToString(resp.Keys[0].KeyInfo.PublicKey),
		)
		return nil
	}
	if err != nil && !isKeyNotFound(err) {
		return fmt.Errorf("failed to get key %q: %w", keyName, err)
	}

	createResp, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
		Keys: []keystore.CreateKeyRequest{{KeyName: keyName, KeyType: keyType}},
	})
	if err != nil {
		return fmt.Errorf("failed to create key %q: %w", keyName, err)
	}
	if len(createResp.Keys) == 0 {
		return fmt.Errorf("keystore returned no keys after creating %q", keyName)
	}
	lggr.Infow("key created",
		"keyName", keyName, "keyType", keyType, "purpose", purpose,
		"publicKey", hex.EncodeToString(createResp.Keys[0].KeyInfo.PublicKey),
	)
	return nil
}

// isKeyNotFound reports whether err indicates the requested key was not found.
// errors.Is is tried first; the string fallback covers keystore versions that
// return an unwrapped ErrKeyNotFound.
func isKeyNotFound(err error) bool {
	return errors.Is(err, keystore.ErrKeyNotFound) ||
		strings.Contains(err.Error(), keystore.ErrKeyNotFound.Error())
}
