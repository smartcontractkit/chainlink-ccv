package keys

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/serialization"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// this is only in standalone mode, not for production
//
//nolint:gosec
const keystorepw = "devenv-seed-transfer"

// EnsureKeyFromSeed creates keyName in the keystore using the provided hex-encoded
// private key, if the key does not already exist. This is used in the devenv to
// share a deterministic ECDSA signing key across HA verifier containers.
func EnsureKeyFromSeed(
	ctx context.Context,
	lggr logger.Logger,
	ks keystore.Keystore,
	keyName, purpose string,
	keyType keystore.KeyType,
	hexPrivateKey string,
) error {
	resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	if err == nil && len(resp.Keys) > 0 {
		lggr.Infow("seeded key already exists, skipping",
			"keyName", keyName, "keyType", keyType, "purpose", purpose,
			"publicKey", hex.EncodeToString(resp.Keys[0].KeyInfo.PublicKey),
		)
		return nil
	}
	if err != nil && !isKeyNotFound(err) {
		return fmt.Errorf("failed to get key %q: %w", keyName, err)
	}

	privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(hexPrivateKey, "0x"))
	if err != nil {
		return fmt.Errorf("failed to decode seed private key hex: %w", err)
	}

	importData, err := encodePrivateKeyForImport(keyName, keyType, privateKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to encode seed key for import: %w", err)
	}

	_, err = ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{{
			NewKeyName: keyName,
			Data:       importData,
			Password:   keystorepw,
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to import seed key %q: %w", keyName, err)
	}

	lggr.Infow("seeded key imported",
		"keyName", keyName, "keyType", keyType, "purpose", purpose,
	)
	return nil
}

// encodePrivateKeyForImport constructs the encrypted import blob that
// keystore.ImportKeys expects. The format mirrors keystore.ExportKeys:
// proto-marshal a serialization.Key, then encrypt with geth's V3 scheme.
func encodePrivateKeyForImport(keyName string, keyType keystore.KeyType, privateKeyBytes []byte) ([]byte, error) {
	keypb := &serialization.Key{
		Name:       keyName,
		KeyType:    string(keyType),
		PrivateKey: privateKeyBytes,
		CreatedAt:  time.Now().Unix(),
		Metadata:   []byte{},
	}
	serialized, err := proto.Marshal(keypb)
	if err != nil {
		return nil, fmt.Errorf("proto marshal: %w", err)
	}

	encData, err := gethkeystore.EncryptDataV3(
		serialized,
		[]byte(keystorepw),
		gethkeystore.LightScryptN,
		gethkeystore.LightScryptP,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return json.Marshal(encData)
}
