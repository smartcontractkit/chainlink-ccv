package keys

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/serialization"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ImportFormat identifies the export format of a Chainlink node key file.
type ImportFormat string

const (
	// ImportFormatOCR2 is the output of `chainlink keys ocr2 export`. Only the EVM chain type is
	// accepted: the bundle's onchain signing key is the secp256k1 key whose address a node
	// operator has registered in the CommitteeVerifier signer set, and it is the only part of the
	// bundle a standalone verifier uses. The offchain and config keys in the bundle belong to OCR
	// rounds, which standalone CCV does not run, and are discarded.
	ImportFormatOCR2 ImportFormat = "ocr2"
	// ImportFormatETH is the output of `chainlink keys eth export`: a Web3 Secret Storage v3 file
	// holding the node's EVM account key. That account is the funded transmitter an executor
	// submits from, so it must carry over rather than be regenerated.
	ImportFormatETH ImportFormat = "eth"
)

// AllImportFormats lists every accepted value of ImportFormat, for validation messages.
var AllImportFormats = []ImportFormat{ImportFormatOCR2, ImportFormatETH}

// DetectFormat identifies an exported Chainlink node key from its contents, so an operator does not
// have to tell us which of the two `chainlink keys ... export` commands produced the file. An OCR2
// bundle declares its key type and chain type; an eth key is a Web3 Secret Storage file carrying an
// address and no key type.
func DetectFormat(data []byte) (ImportFormat, error) {
	var probe struct {
		KeyType   string `json:"keyType"`
		ChainType string `json:"chainType"`
		Address   string `json:"address"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("not a Chainlink key export (invalid JSON): %w", err)
	}
	switch {
	case strings.EqualFold(probe.KeyType, "OCR2") || probe.ChainType != "":
		return ImportFormatOCR2, nil
	case probe.Address != "":
		return ImportFormatETH, nil
	case probe.KeyType != "":
		return "", fmt.Errorf(
			"this is a %q key export; the migration needs the OCR2 bundle (`chainlink keys ocr2 export`) "+
				"or the account key (`chainlink keys eth export`)", probe.KeyType)
	default:
		return "", fmt.Errorf("could not tell what kind of Chainlink key export this is")
	}
}

// Import declares one Chainlink node key to adopt into the standalone keystore in place of
// generating a fresh one. It exists for the CL-mode to standalone migration: a node operator's
// onchain signing key and funded transmitter key have to survive the move, or the committee
// verifier contract needs reconfiguring and the transmitter needs refunding.
type Import struct {
	// Format is the export format of the file at Path. Leave it empty to detect it from the file,
	// which is what the bootstrap config does.
	Format ImportFormat
	// Path is the exported key file.
	Path string
	// PasswordPath is a file holding the password the key was exported under. The password is read
	// from its own file so that the bootstrap config itself stays free of credentials.
	PasswordPath string
<<<<<<< HEAD
	// ExpectedID, when set, must equal the identity encoded in the export: the onchain signing
	// address for ImportFormatOCR2, the account address for ImportFormatETH, both hex without a
	// 0x prefix and case-insensitive. An operator migrating several nodes can mount the wrong
	// node's export, and without this check the node comes up signing with another node's key —
	// which produces verification results the committee rejects, with nothing pointing at the
	// cause. Setting it turns that into a startup failure.
=======
	// ExpectedID must equal the identity encoded in the export: the onchain signing address for
	// ImportFormatOCR2, the account address for ImportFormatETH, hex with or without a 0x prefix,
	// case-insensitive. It is required because it is the check that turns mounting the wrong node's
	// export into a startup failure: without it the node comes up signing with another node's key,
	// which produces verification results the committee rejects, with nothing pointing at the
	// cause.
>>>>>>> origin/main
	//
	// It is enforced against the key already in the keystore as well as against the export, so
	// adding it after a node has booted with the wrong key still fails rather than silently
	// accepting the identity that got there first.
	ExpectedID string
}

// Validate reports whether the import is well formed. It does not touch the filesystem: a missing
// or unreadable file surfaces when the import runs, with the key name in the message.
func (i Import) Validate() error {
	if strings.TrimSpace(i.Path) == "" {
		return fmt.Errorf("field 'path' is required")
	}
	if strings.TrimSpace(i.PasswordPath) == "" {
		return fmt.Errorf("field 'password_path' is required")
	}
<<<<<<< HEAD
=======
	if strings.TrimSpace(i.ExpectedID) == "" {
		return fmt.Errorf("field 'expected_id' is required: it is the check that fails the boot " +
			"when the wrong node's export is mounted")
	}
>>>>>>> origin/main
	switch i.Format {
	// Empty means "detect from the file", which is the normal case: the bootstrap config does not
	// ask an operator which export they took.
	case "", ImportFormatOCR2, ImportFormatETH:
		return nil
	default:
		return fmt.Errorf("unknown format %q: must be one of %s", i.Format, formatList())
	}
}

func formatList() string {
	names := make([]string, len(AllImportFormats))
	for i, f := range AllImportFormats {
		names[i] = string(f)
	}
	return strings.Join(names, ", ")
}

// EnsureImportedKey makes keyName exist by importing spec's key material, and does nothing if the
// key is already present. The existing-key case is the normal path on every restart after a
// successful migration, so the export files and their password file can be unmounted once the node
// has come up once.
//
<<<<<<< HEAD
=======
// An existing key is never overwritten. The scenario that matters is a process that booted once
// without an import configured: its keystore already holds a key it generated, and that key may
// already have been published — the signing address is synced to JD on connect. Silently replacing
// it would orphan whatever registered it, so expected_id is checked against the existing key and a
// mismatch is a hard startup error. Recovery is deliberately manual: remove the key (or the
// bootstrap database, before anything has registered with JD) and start again.
//
>>>>>>> origin/main
// keyType is the type the app declared for keyName. Both supported formats carry a secp256k1
// private key, so a declaration of any other type is a programming error and is rejected rather
// than silently producing a key the app cannot use.
func EnsureImportedKey(
	ctx context.Context,
	lggr logger.Logger,
	ks keystore.Keystore,
	keyName, purpose string,
	keyType keystore.KeyType,
	spec Import,
) error {
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("invalid import for key %q: %w", keyName, err)
	}
	if keyType != keystore.ECDSA_S256 {
		return fmt.Errorf(
			"key %q is declared as %s but %s imports carry a secp256k1 key and can only populate %s",
			keyName, keyType, spec.Format, keystore.ECDSA_S256,
		)
	}

	resp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
<<<<<<< HEAD
	if err == nil && len(resp.Keys) > 0 {
=======
	if err == nil && len(resp.Keys) > 1 {
		// Defensive: names are unique in the keystore, so more than one key for a name means the
		// store is in a state this code cannot reason about. Fail rather than pick one.
		return fmt.Errorf("keystore returned %d keys for name %q, expected exactly one", len(resp.Keys), keyName)
	}
	if err == nil && len(resp.Keys) == 1 {
>>>>>>> origin/main
		if got := resp.Keys[0].KeyInfo.KeyType; got != keyType {
			return fmt.Errorf(
				"key %q already exists with type %s, not %s: remove it or declare a different key name",
				keyName, got, keyType,
			)
		}
		existing := resp.Keys[0].KeyInfo.PublicKey
		// expected_id is checked against the key already in the keystore, not only against the one
		// being imported. Without this, a node that booted once with the wrong export mounted keeps
		// that identity for good: the key exists, the import is skipped, and the check an operator
		// added precisely to catch that mistake never runs.
		if err := checkExpectedID(spec, existing); err != nil {
			return fmt.Errorf("key %q is already in the keystore but %w", keyName, err)
		}
		lggr.Infow("key already exists, skipping import",
			"keyName", keyName, "keyType", keyType, "purpose", purpose, "format", spec.Format,
			"publicKey", hex.EncodeToString(existing),
		)
		return nil
	}
	if err != nil && !isKeyNotFound(err) {
		return fmt.Errorf("failed to get key %q: %w", keyName, err)
	}

	privateKey, id, err := decodeImport(spec)
	if err != nil {
		// The format is deliberately not named here: it is empty in the normal case, where the
		// bootstrap config leaves detection to the file. The wrapped error identifies what it tried
		// to parse.
		return fmt.Errorf("failed to decode the export for key %q from %q: %w", keyName, spec.Path, err)
	}
<<<<<<< HEAD
	if want := strings.TrimSpace(spec.ExpectedID); want != "" {
		if !strings.EqualFold(strings.TrimPrefix(want, "0x"), id) {
			return fmt.Errorf(
				"the export for key %q from %q holds identity %s but expected_id is %s: the wrong node's export is mounted",
				keyName, spec.Path, id, want,
			)
		}
=======
	if want := strings.TrimPrefix(strings.TrimSpace(spec.ExpectedID), "0x"); !strings.EqualFold(want, id) {
		return fmt.Errorf(
			"the export for key %q from %q holds identity %s but expected_id is %s: the wrong node's export is mounted",
			keyName, spec.Path, id, spec.ExpectedID,
		)
>>>>>>> origin/main
	}

	blob, err := encodeForImport(keyName, keyType, privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode key %q for import: %w", keyName, err)
	}
	if _, err := ks.ImportKeys(ctx, keystore.ImportKeysRequest{
		Keys: []keystore.ImportKeyRequest{{
			NewKeyName: keyName,
			Data:       blob,
			Password:   importEnvelopeAuth,
		}},
	}); err != nil {
		return fmt.Errorf("failed to import key %q: %w", keyName, err)
	}

	lggr.Infow("key imported from Chainlink node export",
		"keyName", keyName, "keyType", keyType, "purpose", purpose,
		"format", spec.Format, "path", spec.Path, "id", id,
	)
	return nil
}

// checkExpectedID reports whether a keystore key with the given uncompressed secp256k1 public key
<<<<<<< HEAD
// carries the identity spec pins. An unset expected_id passes: pinning is opt-in, and a deployment
// that never set it keeps working exactly as before.
=======
// carries the identity spec pins.
>>>>>>> origin/main
//
// The address is derived the same way the import path derives it from the export, so the two
// comparisons cannot disagree about what a key's identity is.
func checkExpectedID(spec Import, publicKey []byte) error {
<<<<<<< HEAD
	want := strings.TrimSpace(spec.ExpectedID)
	if want == "" {
		return nil
	}
=======
	want := strings.TrimPrefix(strings.TrimSpace(spec.ExpectedID), "0x")
>>>>>>> origin/main
	address, _, err := EVMAddressFromPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("its public key could not be decoded to compare against expected_id: %w", err)
	}
	got := strings.ToLower(strings.TrimPrefix(address, "0x"))
<<<<<<< HEAD
	if !strings.EqualFold(strings.TrimPrefix(want, "0x"), got) {
		return fmt.Errorf(
			"holds identity %s while expected_id is %s: a different node's key is already in this keystore",
			got, want,
=======
	if !strings.EqualFold(want, got) {
		return fmt.Errorf(
			"holds identity %s while expected_id is %s: a different node's key is already in this keystore",
			got, spec.ExpectedID,
>>>>>>> origin/main
		)
	}
	return nil
}

// InspectImport reports the identity carried by an exported key file — the onchain signing address
// for an OCR2 bundle, the account address for an eth key — without touching a keystore. It lets an
// operator confirm they grabbed the right file before wiring it into a bootstrap config, rather
// than discovering the mistake from a node that started with somebody else's key.
<<<<<<< HEAD
func InspectImport(spec Import) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
=======
//
// It deliberately skips Validate: its whole point is reading the identity an operator does not yet
// know, so it cannot require expected_id up front. decodeImport's errors cover unreadable files and
// unrecognized formats.
func InspectImport(spec Import) (string, error) {
>>>>>>> origin/main
	_, id, err := decodeImport(spec)
	if err != nil {
		return "", fmt.Errorf("failed to decode the export %q: %w", spec.Path, err)
	}
	return id, nil
}

// decodeImport reads and decrypts the export at spec.Path, returning the raw private key bytes and
// the identity the export claims — the onchain signing address for OCR2 bundles, the account
// address for eth keys — as lowercase hex without a 0x prefix.
func decodeImport(spec Import) (privateKey []byte, id string, err error) {
	data, err := os.ReadFile(spec.Path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read key file: %w", err)
	}
	passwordBytes, err := os.ReadFile(spec.PasswordPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read password file %q: %w", spec.PasswordPath, err)
	}
	// Chainlink's own password files are read the same way: a trailing newline from an editor or
	// a heredoc is not part of the password.
	password := strings.TrimRight(string(passwordBytes), "\r\n")

	format := spec.Format
	if format == "" {
		if format, err = DetectFormat(data); err != nil {
			return nil, "", err
		}
	}

	switch format {
	case ImportFormatOCR2:
		return decodeOCR2Bundle(data, password)
	case ImportFormatETH:
		return decodeETHKey(data, password)
	default:
		return nil, "", fmt.Errorf("unknown format %q", format)
	}
}

// The OCR2 export format is decoded here directly rather than through
// chainlink-common/keystore/corekeys/ocr2key. That package's FromEncryptedJSON switches over every
// supported chain type, so importing it links the Cosmos, Solana, Starknet and TON keyrings — and
// their module requirements — into the verifier and executor binaries, none of which a standalone
// EVM deployment can use. The three layers below are a serialization contract, not an API: they
// describe files already written to operator disks by released node versions, so they are fixed for
// every export this migration will ever read.
const (
	// ocr2ChainTypeEVM is corekeys.ChainType's EVM value as it appears in an exported bundle.
	ocr2ChainTypeEVM = "evm"
	// ocr2PasswordPrefix is the prefix ocr2key prepends to the export password before deriving the
	// V3 encryption key.
	ocr2PasswordPrefix = "ocr2key"
)

// ocr2Export is the outer JSON of a `chainlink keys ocr2 export` file.
type ocr2Export struct {
	ChainType        string                  `json:"chainType"`
	OnchainPublicKey string                  `json:"onchainPublicKey"`
	Crypto           gethkeystore.CryptoJSON `json:"crypto"`
}

// ocr2Bundle is the JSON inside the encrypted payload. Only the onchain keyring is read: the
// offchain and config keys drive OCR rounds, which standalone CCV does not run. EVMKeyring is the
// pre-consolidation field name and is still present in bundles created by older node versions.
type ocr2Bundle struct {
	ChainType  string `json:"ChainType"`
	Keyring    []byte `json:"Keyring"`
	EVMKeyring []byte `json:"EVMKeyring,omitempty"`
}

// onchainKey returns the raw onchain signing key, preferring the current field and falling back to
// the legacy one, mirroring ocr2key's own migration handling.
func (b ocr2Bundle) onchainKey() []byte {
	if len(b.Keyring) > 0 {
		return b.Keyring
	}
	return b.EVMKeyring
}

// decodeOCR2Bundle extracts the onchain signing key from a `chainlink keys ocr2 export` file.
func decodeOCR2Bundle(data []byte, password string) (privateKey []byte, id string, err error) {
	var export ocr2Export
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, "", fmt.Errorf("failed to parse OCR2 export (not an ocr2 export?): %w", err)
	}
	// The chain type is checked before decrypting so that pointing at a Solana or Aptos bundle
	// reports that directly instead of failing later on an unexpected key length.
	if !strings.EqualFold(export.ChainType, ocr2ChainTypeEVM) {
		return nil, "", fmt.Errorf(
			"OCR2 export has chain type %q but only %q bundles hold an EVM onchain signing key; "+
				"export the bundle `chainlink keys ocr2 list` shows for EVM",
			export.ChainType, ocr2ChainTypeEVM,
		)
	}

	decrypted, err := gethkeystore.DecryptDataV3(export.Crypto, ocr2PasswordPrefix+password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt OCR2 key bundle (wrong password?): %w", err)
	}
	var bundle ocr2Bundle
	if err := json.Unmarshal(decrypted, &bundle); err != nil {
		return nil, "", fmt.Errorf("failed to parse decrypted OCR2 key bundle: %w", err)
	}
	onchain := bundle.onchainKey()
	if len(onchain) == 0 {
		return nil, "", fmt.Errorf("OCR2 key bundle carries no onchain keyring")
	}

	privKey, err := gethcrypto.ToECDSA(onchain)
	if err != nil {
		return nil, "", fmt.Errorf("OCR2 onchain keyring is not a valid secp256k1 key: %w", err)
	}
	derived := strings.ToLower(hex.EncodeToString(gethcrypto.PubkeyToAddress(privKey.PublicKey).Bytes()))
	// onchainPublicKey is the address the node published to JD, and therefore the address sitting in
	// the CommitteeVerifier signer set. Deriving it independently from the extracted key is what
	// confirms this import will sign as that same address — without it, a bundle whose inner layer
	// did not decode as expected would import a key that silently signs as somebody else.
	if published := strings.ToLower(strings.TrimPrefix(export.OnchainPublicKey, "0x")); published != derived {
		return nil, "", fmt.Errorf(
			"OCR2 onchain keyring derives address %s but the export publishes %s", derived, published,
		)
	}
	return onchain, derived, nil
}

// decodeETHKey extracts the account key from a `chainlink keys eth export` file.
func decodeETHKey(data []byte, password string) (privateKey []byte, id string, err error) {
	key, err := gethkeystore.DecryptKey(data, password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt ETH key (wrong password, or not an eth export?): %w", err)
	}
	if key.PrivateKey == nil {
		return nil, "", fmt.Errorf("ETH key file carries no private key")
	}
	derived := gethcrypto.PubkeyToAddress(key.PrivateKey.PublicKey)
	if derived != key.Address {
		return nil, "", fmt.Errorf(
			"ETH key derives address %s but the file records %s",
			strings.ToLower(derived.Hex()), strings.ToLower(key.Address.Hex()),
		)
	}
	return gethcrypto.FromECDSA(key.PrivateKey), strings.ToLower(hex.EncodeToString(derived.Bytes())), nil
}

// importEnvelopeAuth is the passphrase for the envelope handed to keystore.ImportKeys, whose API
// takes encrypted bytes rather than raw key material. It guards nothing: the envelope is built and
// consumed within one function call, never reaches disk, and ImportKeys immediately re-encrypts the
// key under the keystore's own password. It is a constant, with fast scrypt parameters, because
// using the real keystore password here would run an expensive KDF twice per imported key at every
// boot and protect nothing that is not already in memory.
const importEnvelopeAuth = "ccv-key-import"

// encodeForImport wraps raw private key bytes in the envelope keystore.ImportKeys expects: a
// serialization.Key protobuf, encrypted as a Web3 Secret Storage v3 blob.
<<<<<<< HEAD
=======
//
// The decode-then-re-encode dance is unavoidable, not redundant. keystore.ImportKeys accepts
// exactly one input — this envelope, a serialization.Key in a web3 v3 blob — and builds the
// stored key from it; a Chainlink export decrypts to a different payload entirely (bundle JSON
// for OCR2, geth key JSON for eth), so it cannot be imported as-is. A Chainlink-side keyName
// would not remove this step either: those export formats are frozen in released node versions
// on operator disks, and the target key name here comes from the ImportKeys request's
// NewKeyName, not from anything in the export. The decrypt is also what verifies the password
// and cross-checks the identity before the key is trusted.
>>>>>>> origin/main
func encodeForImport(keyName string, keyType keystore.KeyType, privateKey []byte) ([]byte, error) {
	serialized, err := proto.Marshal(&serialization.Key{
		Name:       keyName,
		KeyType:    string(keyType),
		PrivateKey: privateKey,
		CreatedAt:  time.Now().Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	encrypted, err := gethkeystore.EncryptDataV3(
		serialized,
		[]byte(importEnvelopeAuth),
		keystore.FastScryptParams.N,
		keystore.FastScryptParams.P,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}
	blob, err := json.Marshal(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted key: %w", err)
	}
	return blob, nil
}
