package bootstrap

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ensureKey ensures that a key is present in the keystore.
// If the key is not present, it is created.
// If the key is present, it is used.
func ensureKey(
	ctx context.Context,
	lggr logger.Logger,
	keyStore keystore.Keystore,
	keyName, purpose string,
	keyType keystore.KeyType,
) error {
	getKeyResponse, err := keyStore.GetKeys(ctx, keystore.GetKeysRequest{
		KeyNames: []string{keyName},
	})
	keyNotFound := err != nil && (errors.Is(err, keystore.ErrKeyNotFound) || strings.Contains(err.Error(), "key not found"))
	if err != nil && !keyNotFound {
		return fmt.Errorf("failed to get key: %w", err)
	}
	if keyNotFound || len(getKeyResponse.Keys) == 0 {
		// If no key exists, create a new one.
		createKeyResponse, err := keyStore.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{
				{
					KeyName: keyName,
					KeyType: keyType,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}
		if len(createKeyResponse.Keys) == 0 {
			return fmt.Errorf("failed to create key: no keys returned by keystore")
		}
		lggr.Infow("key created",
			"keyName", keyName,
			"keyType", keyType,
			"purpose", purpose,
			"publicKey", hex.EncodeToString(createKeyResponse.Keys[0].KeyInfo.PublicKey),
		)
	} else {
		lggr.Infow("key found in keystore, using existing one",
			"keyName", keyName,
			"keyType", keyType,
			"purpose", purpose,
			"publicKey", hex.EncodeToString(getKeyResponse.Keys[0].KeyInfo.PublicKey),
		)
	}
	return nil
}
