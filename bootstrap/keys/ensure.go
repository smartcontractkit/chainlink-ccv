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
			keyLogFields(lggr, keyName, purpose, keyType, resp.Keys[0].KeyInfo.PublicKey)...)
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
		keyLogFields(lggr, keyName, purpose, keyType, createResp.Keys[0].KeyInfo.PublicKey)...)
	return nil
}

// keyLogFields describes a key for the startup log. For secp256k1 keys it includes the derived EVM
// address, because that is the value an operator acts on — the executor's generated transmitter has
// to be funded before it can transmit, and deriving the address from the public key is a keccak hash
// rather than something to do by hand. The process that holds the key prints it instead.
//
// A public key that does not unmarshal is logged without the address rather than failing the boot:
// the keystore holds a usable key either way, and only the convenience field is missing.
func keyLogFields(
	lggr logger.Logger,
	keyName, purpose string,
	keyType keystore.KeyType,
	publicKey []byte,
) []any {
	// Capacity covers the evmAddress pair appended below, so the secp256k1 path does not reallocate.
	fields := make([]any, 0, 10)
	fields = append(fields,
		"keyName", keyName, "keyType", keyType, "purpose", purpose,
		"publicKey", hex.EncodeToString(publicKey),
	)
	if keyType != keystore.ECDSA_S256 {
		return fields
	}
	address, _, err := EVMAddressFromPublicKey(publicKey)
	if err != nil {
		lggr.Warnw("could not derive the EVM address for this key; derive it from publicKey if you need it",
			"keyName", keyName, "err", err)
		return fields
	}
	return append(fields, "evmAddress", address)
}

// isKeyNotFound reports whether err indicates the requested key was not found.
// errors.Is is tried first; the string fallback covers keystore versions that
// return an unwrapped ErrKeyNotFound.
func isKeyNotFound(err error) bool {
	return errors.Is(err, keystore.ErrKeyNotFound) ||
		strings.Contains(err.Error(), keystore.ErrKeyNotFound.Error())
}
