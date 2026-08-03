package keys

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const testExportPassword = "export-password"

// The fixtures below are built from the same primitives a Chainlink node uses to write its
// exports — geth's V3 encryption, the "ocr2key" password prefix, and the bundle's JSON layering —
// so they exercise the decoder against the real on-disk shape rather than a paraphrase of it.
// TestE2EMigration_CLToStandalone covers the same decoders against files a live node produced.

// fullOCR2Bundle is the complete inner JSON a node writes, including the fields the decoder
// deliberately ignores. Encoding them keeps the fixture faithful and proves they are skipped
// rather than tripping the decoder up.
type fullOCR2Bundle struct {
	ChainType       string `json:"ChainType"`
	OffchainKeyring []byte `json:"OffchainKeyring"`
	Keyring         []byte `json:"Keyring"`
	ID              []byte `json:"ID"`

	EVMKeyring []byte `json:"EVMKeyring,omitempty"`
}

// writeOCR2Export writes a `chainlink keys ocr2 export`-shaped file and returns its path.
func writeOCR2Export(t *testing.T, dir string, priv *ecdsa.PrivateKey, opts ...func(*ocr2Export, *fullOCR2Bundle)) string {
	t.Helper()
	bundle := fullOCR2Bundle{
		ChainType: ocr2ChainTypeEVM,
		Keyring:   gethcrypto.FromECDSA(priv),
		// The offchain keyring is an ed25519 signing key plus an X25519 encryption key; its exact
		// contents are irrelevant here, only that it is present and ignored.
		OffchainKeyring: make([]byte, 64),
		ID:              make([]byte, 32),
	}
	export := ocr2Export{
		ChainType:        ocr2ChainTypeEVM,
		OnchainPublicKey: hex.EncodeToString(gethcrypto.PubkeyToAddress(priv.PublicKey).Bytes()),
	}
	for _, opt := range opts {
		opt(&export, &bundle)
	}

	inner, err := json.Marshal(bundle)
	require.NoError(t, err)
	crypto, err := gethkeystore.EncryptDataV3(
		inner,
		[]byte(ocr2PasswordPrefix+testExportPassword),
		keystore.FastScryptParams.N,
		keystore.FastScryptParams.P,
	)
	require.NoError(t, err)
	export.Crypto = crypto

	data, err := json.Marshal(export)
	require.NoError(t, err)
	path := filepath.Join(dir, "ocr2.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// writeETHExport writes a `chainlink keys eth export`-shaped file and returns its path.
func writeETHExport(t *testing.T, dir string, priv *ecdsa.PrivateKey) string {
	t.Helper()
	address := gethcrypto.PubkeyToAddress(priv.PublicKey)
	id, err := uuid.FromBytes(address.Bytes()[:16])
	require.NoError(t, err)
	data, err := gethkeystore.EncryptKey(
		&gethkeystore.Key{Id: id, Address: address, PrivateKey: priv},
		testExportPassword,
		keystore.FastScryptParams.N,
		keystore.FastScryptParams.P,
	)
	require.NoError(t, err)
	path := filepath.Join(dir, "eth.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func writePasswordFile(t *testing.T, dir, password string) string {
	t.Helper()
	path := filepath.Join(dir, "password.txt")
	require.NoError(t, os.WriteFile(path, []byte(password), 0o600))
	return path
}

func newTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := gethcrypto.GenerateKey()
	require.NoError(t, err)
	return priv
}

func TestDecodeOCR2Bundle(t *testing.T) {
	t.Parallel()

	t.Run("extracts the onchain signing key", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		path := writeOCR2Export(t, dir, priv)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		got, id, err := decodeOCR2Bundle(data, testExportPassword)
		require.NoError(t, err)

		assert.Equal(t, gethcrypto.FromECDSA(priv), got)
		assert.Equal(t, strings.ToLower(gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()[2:]), id)
	})

	t.Run("falls back to the legacy EVMKeyring field", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		path := writeOCR2Export(t, dir, priv, func(_ *ocr2Export, b *fullOCR2Bundle) {
			b.EVMKeyring = b.Keyring
			b.Keyring = nil
		})

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		got, _, err := decodeOCR2Bundle(data, testExportPassword)
		require.NoError(t, err)
		assert.Equal(t, gethcrypto.FromECDSA(priv), got)
	})

	t.Run("rejects a non-EVM bundle by name", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := writeOCR2Export(t, dir, newTestECDSAKey(t), func(e *ocr2Export, _ *fullOCR2Bundle) {
			e.ChainType = "solana"
		})

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		_, _, err = decodeOCR2Bundle(data, testExportPassword)
		require.ErrorContains(t, err, "solana")
	})

	t.Run("rejects a wrong password", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := writeOCR2Export(t, dir, newTestECDSAKey(t))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		_, _, err = decodeOCR2Bundle(data, "not-the-password")
		require.ErrorContains(t, err, "failed to decrypt")
	})

	t.Run("rejects a bundle whose key does not match the published address", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		other := newTestECDSAKey(t)
		path := writeOCR2Export(t, dir, newTestECDSAKey(t), func(e *ocr2Export, _ *fullOCR2Bundle) {
			e.OnchainPublicKey = hex.EncodeToString(gethcrypto.PubkeyToAddress(other.PublicKey).Bytes())
		})

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		_, _, err = decodeOCR2Bundle(data, testExportPassword)
		require.ErrorContains(t, err, "derives address")
	})

	t.Run("rejects a bundle with no onchain keyring", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := writeOCR2Export(t, dir, newTestECDSAKey(t), func(_ *ocr2Export, b *fullOCR2Bundle) {
			b.Keyring = nil
		})

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		_, _, err = decodeOCR2Bundle(data, testExportPassword)
		require.ErrorContains(t, err, "no onchain keyring")
	})
}

func TestDecodeETHKey(t *testing.T) {
	t.Parallel()

	t.Run("extracts the account key", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		path := writeETHExport(t, dir, priv)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		got, id, err := decodeETHKey(data, testExportPassword)
		require.NoError(t, err)

		assert.Equal(t, gethcrypto.FromECDSA(priv), got)
		assert.Equal(t, strings.ToLower(gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()[2:]), id)
	})

	t.Run("rejects a wrong password", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := writeETHExport(t, dir, newTestECDSAKey(t))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		_, _, err = decodeETHKey(data, "not-the-password")
		require.ErrorContains(t, err, "failed to decrypt")
	})
}

func TestEnsureImportedKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lggr := logger.TestSugared(t)

	// wantPublicKey is the SEC1 uncompressed public key the keystore derives for an imported key.
	wantPublicKey := func(priv *ecdsa.PrivateKey) []byte {
		return gethcrypto.FromECDSAPub(&priv.PublicKey)
	}

	t.Run("imports an OCR2 onchain signing key", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatOCR2,
			Path:         writeOCR2Export(t, dir, priv),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   gethcrypto.PubkeyToAddress(priv.PublicKey).Hex(),
		}
		ks := newTestKeystore(t)

		require.NoError(t, EnsureImportedKey(ctx, lggr, ks, "signing-key", "signing", keystore.ECDSA_S256, spec))

		resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"signing-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		assert.Equal(t, keystore.ECDSA_S256, resp.Keys[0].KeyInfo.KeyType)
		assert.Equal(t, wantPublicKey(priv), resp.Keys[0].KeyInfo.PublicKey)
	})

	t.Run("imports an eth transmitter key", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, priv),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   gethcrypto.PubkeyToAddress(priv.PublicKey).Hex(),
		}
		ks := newTestKeystore(t)

		require.NoError(t, EnsureImportedKey(ctx, lggr, ks, "tx-key", "transmitting", keystore.ECDSA_S256, spec))

		resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"tx-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		assert.Equal(t, wantPublicKey(priv), resp.Keys[0].KeyInfo.PublicKey)
	})

	t.Run("tolerates a trailing newline in the password file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, priv),
			PasswordPath: writePasswordFile(t, dir, testExportPassword+"\n"),
			ExpectedID:   gethcrypto.PubkeyToAddress(priv.PublicKey).Hex(),
		}

		require.NoError(t, EnsureImportedKey(ctx, lggr, newTestKeystore(t), "tx-key", "transmitting", keystore.ECDSA_S256, spec))
	})

	t.Run("is a no-op when the key already exists", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		ks := newTestKeystore(t)
		created, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{{KeyName: "tx-key", KeyType: keystore.ECDSA_S256}},
		})
		require.NoError(t, err)
		address, _, err := EVMAddressFromPublicKey(created.Keys[0].KeyInfo.PublicKey)
		require.NoError(t, err)

		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, newTestECDSAKey(t)),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   address,
		}

		require.NoError(t, EnsureImportedKey(ctx, lggr, ks, "tx-key", "transmitting", keystore.ECDSA_S256, spec))

		resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{"tx-key"}})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		assert.Equal(t, created.Keys[0].KeyInfo.PublicKey, resp.Keys[0].KeyInfo.PublicKey,
			"a restart after migration must not replace the imported key")
	})

	t.Run("accepts a matching expected_id", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, priv),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   gethcrypto.PubkeyToAddress(priv.PublicKey).Hex(), // 0x-prefixed, EIP-55 cased
		}

		require.NoError(t, EnsureImportedKey(ctx, lggr, newTestKeystore(t), "tx-key", "transmitting", keystore.ECDSA_S256, spec))
	})

	t.Run("rejects a mismatched expected_id", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		other := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, newTestECDSAKey(t)),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   gethcrypto.PubkeyToAddress(other.PublicKey).Hex(),
		}

		err := EnsureImportedKey(ctx, lggr, newTestKeystore(t), "tx-key", "transmitting", keystore.ECDSA_S256, spec)
		require.ErrorContains(t, err, "wrong node's export is mounted")
	})

	// The import is skipped once the key exists, so an expected_id that is only checked on the
	// import path would never run again after the first boot. A node brought up with the wrong key
	// would keep that identity, which is the exact outcome expected_id exists to prevent.
	t.Run("rejects a mismatched expected_id against a key already in the keystore", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		other := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, newTestECDSAKey(t)),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   gethcrypto.PubkeyToAddress(other.PublicKey).Hex(),
		}
		ks := newTestKeystore(t)
		_, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{{KeyName: "tx-key", KeyType: keystore.ECDSA_S256}},
		})
		require.NoError(t, err)

		err = EnsureImportedKey(ctx, lggr, ks, "tx-key", "transmitting", keystore.ECDSA_S256, spec)
		require.ErrorContains(t, err, "already in the keystore")
		require.ErrorContains(t, err, "tx-key")
	})

	t.Run("accepts a matching expected_id against a key already in the keystore", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		ks := newTestKeystore(t)
		created, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{{KeyName: "tx-key", KeyType: keystore.ECDSA_S256}},
		})
		require.NoError(t, err)
		address, _, err := EVMAddressFromPublicKey(created.Keys[0].KeyInfo.PublicKey)
		require.NoError(t, err)

		// The export names a different key. It is never read, because the keystore already holds the
		// pinned identity — which is the normal restart path after a migration, with the export files
		// unmounted.
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, newTestECDSAKey(t)),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   address,
		}

		require.NoError(t, EnsureImportedKey(ctx, lggr, ks, "tx-key", "transmitting", keystore.ECDSA_S256, spec))
	})

	t.Run("rejects a non-secp256k1 target key type", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, priv),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   gethcrypto.PubkeyToAddress(priv.PublicKey).Hex(),
		}

		err := EnsureImportedKey(ctx, lggr, newTestKeystore(t), "csa-key", "csa", keystore.Ed25519, spec)
		require.ErrorContains(t, err, "secp256k1")
	})

	t.Run("rejects an existing key of a different type", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		priv := newTestECDSAKey(t)
		spec := Import{
			Format:       ImportFormatETH,
			Path:         writeETHExport(t, dir, priv),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   gethcrypto.PubkeyToAddress(priv.PublicKey).Hex(),
		}
		ks := newTestKeystore(t)
		_, err := ks.CreateKeys(ctx, keystore.CreateKeysRequest{
			Keys: []keystore.CreateKeyRequest{{KeyName: "tx-key", KeyType: keystore.Ed25519}},
		})
		require.NoError(t, err)

		err = EnsureImportedKey(ctx, lggr, ks, "tx-key", "transmitting", keystore.ECDSA_S256, spec)
		require.ErrorContains(t, err, "already exists with type")
	})

	t.Run("reports a missing key file with the key name", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		spec := Import{
			Format:       ImportFormatETH,
			Path:         filepath.Join(dir, "absent.json"),
			PasswordPath: writePasswordFile(t, dir, testExportPassword),
			ExpectedID:   "0x0123456789abcdef0123456789abcdef01234567",
		}

		err := EnsureImportedKey(ctx, lggr, newTestKeystore(t), "tx-key", "transmitting", keystore.ECDSA_S256, spec)
		require.ErrorContains(t, err, "tx-key")
	})
}

func TestImportValidate(t *testing.T) {
	t.Parallel()

	valid := Import{Format: ImportFormatOCR2, Path: "/k.json", PasswordPath: "/p.txt", ExpectedID: "0xabc"}
	tests := []struct {
		name    string
		imp     Import
		wantErr string
	}{
		{name: "valid", imp: valid},
		{name: "missing path", imp: Import{Format: ImportFormatETH, PasswordPath: "/p.txt", ExpectedID: "0xabc"}, wantErr: "'path'"},
		{name: "missing password path", imp: Import{Format: ImportFormatETH, Path: "/k.json", ExpectedID: "0xabc"}, wantErr: "'password_path'"},
		{name: "missing expected_id", imp: Import{Format: ImportFormatETH, Path: "/k.json", PasswordPath: "/p.txt"}, wantErr: "'expected_id'"},
		{name: "format omitted is detected from the file", imp: Import{Path: "/k.json", PasswordPath: "/p.txt", ExpectedID: "0xabc"}},
		{name: "unknown format", imp: Import{Format: "csa", Path: "/k.json", PasswordPath: "/p.txt", ExpectedID: "0xabc"}, wantErr: "ocr2, eth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.imp.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestDetectFormat(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	ocr2Path := writeOCR2Export(t, dir, newTestECDSAKey(t))
	ocr2Data, err := os.ReadFile(ocr2Path)
	require.NoError(t, err)
	got, err := DetectFormat(ocr2Data)
	require.NoError(t, err)
	assert.Equal(t, ImportFormatOCR2, got)

	ethPath := writeETHExport(t, dir, newTestECDSAKey(t))
	ethData, err := os.ReadFile(ethPath)
	require.NoError(t, err)
	got, err = DetectFormat(ethData)
	require.NoError(t, err)
	assert.Equal(t, ImportFormatETH, got)

	// A CSA export names its type, so the error can say what was mounted instead of guessing.
	_, err = DetectFormat([]byte(`{"keyType":"CSA","publicKey":"abcd","crypto":{}}`))
	require.ErrorContains(t, err, "CSA")

	_, err = DetectFormat([]byte("not json"))
	require.ErrorContains(t, err, "not a Chainlink key export")
}

func TestEnsureImportedKeyDetectsFormat(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	priv := newTestECDSAKey(t)

	// Format left empty: the normal path, since the bootstrap config does not ask for it.
	spec := Import{
		Path:         writeOCR2Export(t, dir, priv),
		PasswordPath: writePasswordFile(t, dir, testExportPassword),
		ExpectedID:   gethcrypto.PubkeyToAddress(priv.PublicKey).Hex(),
	}
	ks := newTestKeystore(t)
	require.NoError(t, EnsureImportedKey(
		context.Background(), logger.TestSugared(t), ks, "signing-key", "signing", keystore.ECDSA_S256, spec))

	resp, err := ks.GetKeys(context.Background(), keystore.GetKeysRequest{KeyNames: []string{"signing-key"}})
	require.NoError(t, err)
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, gethcrypto.FromECDSAPub(&priv.PublicKey), resp.Keys[0].KeyInfo.PublicKey)
}
