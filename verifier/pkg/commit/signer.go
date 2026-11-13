package commit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

// AutoSignerAddress is the signer_address value the postgres auto-generate backend uses to opt out
// of address validation explicitly: the verifier adopts whatever address the keystore holds instead
// of asserting a configured one. It is the "I intentionally don't pin the signer address" signal, and
// it is exclusive — an empty signer_address (the "I forgot to set it" case) is still rejected.
const AutoSignerAddress = "auto"

// ValidateSignerAddress checks that the configured identity and keystore identity describe the same key.
// Either side may be a 20-byte EVM address or a 33/65-byte SEC1 public key; hex may omit the 0x prefix.
// [AutoSignerAddress] explicitly opts out; empty remains an error rather than implying auto-adoption.
func ValidateSignerAddress(configured string, actual protocol.UnknownAddress) error {
	if configured == AutoSignerAddress {
		return nil
	}
	decoded, err := decodeSignerIdentity(configured)
	if err != nil {
		return err
	}
	if keysMatch(decoded, actual.Bytes()) {
		return nil
	}
	return signerIdentityMismatch(configured, actual)
}

// ResolveSignerIdentity returns the configured identity when it matches publicKey.
// [AutoSignerAddress] adopts publicKey without deriving a chain-specific address.
func ResolveSignerIdentity(configured string, publicKey []byte) (protocol.UnknownAddress, error) {
	if configured == AutoSignerAddress {
		return publicKey, nil
	}
	decoded, err := decodeSignerIdentity(configured)
	if err != nil {
		return nil, err
	}
	if keysMatch(decoded, publicKey) {
		return decoded, nil
	}
	return nil, signerIdentityMismatch(configured, publicKey)
}

func decodeSignerIdentity(configured string) (protocol.UnknownAddress, error) {
	decoded, err := hex.DecodeString(strings.TrimPrefix(configured, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid signer_address %q: %w", configured, err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("invalid signer_address %q: empty address", configured)
	}
	return decoded, nil
}

func signerIdentityMismatch(configured string, actual protocol.UnknownAddress) error {
	return fmt.Errorf(
		"signing key does not match signer_address: configured %s, keystore %s; "+
			"check signer_address and, for migration, ensure [key_import] imported the expected verifier signing key before first boot",
		configured, actual.String(),
	)
}

// keysMatch compares raw bytes first, then compares EVM addresses derived from SEC1 keys.
// This accepts different encodings of one key without matching truncated or trailing bytes.
func keysMatch(configured, actual []byte) bool {
	if bytes.Equal(configured, actual) {
		return true
	}
	configuredAddress, ok := addressForKey(configured)
	if !ok {
		return false
	}
	actualAddress, ok := addressForKey(actual)
	return ok && bytes.Equal(configuredAddress, actualAddress)
}

// addressForKey returns an EVM address unchanged or derives one from a SEC1 public key.
func addressForKey(key []byte) ([]byte, bool) {
	if len(key) == common.AddressLength {
		return key, true
	}
	pubKey, err := crypto.UnmarshalPubkey(key)
	if err != nil {
		if pubKey, err = crypto.DecompressPubkey(key); err != nil {
			return nil, false
		}
	}
	address := crypto.PubkeyToAddress(*pubKey)
	return address.Bytes(), true
}

// ECDSASigner implements MessageSigner using ECDSA with the new chain-agnostic message format.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
}

// NewECDSAMessageSignerFromString creates a new ECDSA message signer.
func NewECDSAMessageSignerFromString(privateKeyString string) (*ECDSASigner, []byte, protocol.UnknownAddress, error) {
	privateKey, err := ReadPrivateKeyFromString(privateKeyString)
	if err != nil {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("failed to read private key from environment variable: %w", err)
	}
	return NewECDSAMessageSigner(privateKey)
}

// NewECDSAMessageSigner creates a new ECDSA message signer.
func NewECDSAMessageSigner(privateKeyBytes []byte) (*ECDSASigner, []byte, protocol.UnknownAddress, error) {
	if len(privateKeyBytes) == 0 {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("private key cannot be empty")
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("failed to convert bytes to ECDSA private key: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("failed to cast public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	address, err := EVMAddressFromPublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return &ECDSASigner{
		privateKey: privateKey,
	}, publicKeyBytes, address, nil
}

// Sign signs some data with the new chain-agnostic format.
func (ecdsa *ECDSASigner) Sign(data []byte) ([]byte, error) {
	signature, err := crypto.Sign(data, ecdsa.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return normalizeAndEncodeSignature(data, signature)
}

// ReadPrivateKeyFromString reads a private key from a string and returns the bytes.
// It expects a hex string which could have the "0x" prefix.
func ReadPrivateKeyFromString(privateKey string) ([]byte, error) {
	privateKey = strings.TrimPrefix(privateKey, "0x")
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got: %d", len(privateKeyBytes))
	}
	return privateKeyBytes, nil
}

// ECDSASignerWithKeystoreSigner implements ECDSA with an injected signer object.
// This is useful when the private key material is not directly accessible.
type ECDSASignerWithKeystoreSigner struct {
	keystoreSigner verifier.MessageSigner
}

func NewECDSASignerWithKeystoreSigner(keystoreSigner verifier.MessageSigner) *ECDSASignerWithKeystoreSigner {
	return &ECDSASignerWithKeystoreSigner{
		keystoreSigner: keystoreSigner,
	}
}

func (s *ECDSASignerWithKeystoreSigner) Sign(data []byte) ([]byte, error) {
	signature, err := s.keystoreSigner.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return normalizeAndEncodeSignature(data, signature)
}

func normalizeAndEncodeSignature(hash, signature []byte) ([]byte, error) {
	r, s, err := protocol.NormalizeToV27(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	check := make([]byte, 65)
	copy(check[0:32], r[:])
	copy(check[32:64], s[:])
	if _, err = crypto.SigToPub(hash, check); err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	encoded, err := protocol.EncodeSingleECDSASignature(protocol.Data{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}
	return encoded, nil
}

// KeystoreSignerAdapter wraps the keystore.Signer interface to implement verifier.MessageSigner.
// This allows using the keystore library for key management while maintaining compatibility
// with the existing verifier signing interface.
type KeystoreSignerAdapter struct {
	ks      keystore.Signer
	keyName string
}

// NewKeystoreSignerAdapter creates a new adapter that wraps a keystore.Signer.
func NewKeystoreSignerAdapter(ks keystore.Signer, keyName string) *KeystoreSignerAdapter {
	return &KeystoreSignerAdapter{
		ks:      ks,
		keyName: keyName,
	}
}

// Sign implements verifier.MessageSigner by delegating to the keystore.
// The data parameter should be a 32-byte hash (required by ECDSA_S256).
func (a *KeystoreSignerAdapter) Sign(data []byte) ([]byte, error) {
	resp, err := a.ks.Sign(context.Background(), keystore.SignRequest{
		KeyName: a.keyName,
		Data:    data,
	})
	if err != nil {
		return nil, fmt.Errorf("keystore sign failed: %w", err)
	}
	return resp.Signature, nil
}

// NewECDSASignerFromKeystore returns a signer and its SEC1 uncompressed public key.
func NewECDSASignerFromKeystore(ctx context.Context, ks keystore.Keystore, keyName string) (verifier.MessageSigner, []byte, error) {
	//nolint:noeagerio // fail-fast by design: a verifier without its signing key can do no work, so the keystore read happens at startup rather than at first sign
	keysResp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get key from keystore: %w", err)
	}
	if len(keysResp.Keys) == 0 {
		return nil, nil, fmt.Errorf("key %q not found in keystore", keyName)
	}

	keyInfo := keysResp.Keys[0].KeyInfo
	if keyInfo.KeyType != keystore.ECDSA_S256 {
		return nil, nil, fmt.Errorf("key %q has unexpected type %s, expected %s", keyName, keyInfo.KeyType, keystore.ECDSA_S256)
	}
	if len(keyInfo.PublicKey) != 65 {
		return nil, nil, fmt.Errorf("unexpected public key length %d, expected 65", len(keyInfo.PublicKey))
	}

	return NewECDSASignerWithKeystoreSigner(NewKeystoreSignerAdapter(ks, keyName)), keyInfo.PublicKey, nil
}

// EVMAddressFromPublicKey derives an Ethereum address from a SEC1 uncompressed public key.
func EVMAddressFromPublicKey(publicKey []byte) (protocol.UnknownAddress, error) {
	if len(publicKey) != 65 {
		return nil, fmt.Errorf("unexpected public key length %d, expected 65", len(publicKey))
	}
	ecdsaPublicKey, err := crypto.UnmarshalPubkey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	address := crypto.PubkeyToAddress(*ecdsaPublicKey)
	return address.Bytes(), nil
}

// NewSignerFromKeystore retains the address-returning API for EVM callers.
func NewSignerFromKeystore(ctx context.Context, ks keystore.Keystore, keyName string) (verifier.MessageSigner, []byte, protocol.UnknownAddress, error) {
	signer, publicKey, err := NewECDSASignerFromKeystore(ctx, ks, keyName)
	if err != nil {
		return nil, nil, protocol.UnknownAddress{}, err
	}
	address, err := EVMAddressFromPublicKey(publicKey)
	if err != nil {
		return nil, nil, protocol.UnknownAddress{}, err
	}
	return signer, publicKey, address, nil
}
