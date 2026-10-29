package commit

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"

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

// ValidateSignerAddress checks that configured matches the keystore's derived address.
// Use ValidateSignerIdentity to also accept the uncompressed public key.
func ValidateSignerAddress(configured string, actual protocol.UnknownAddress) error {
	return ValidateSignerIdentity(configured, actual, nil)
}

// ValidateSignerIdentity checks that configured hex matches either the derived address or public key.
// This supports EVM addresses and Canton public keys without chain-family-specific handling.
//
// [AutoSignerAddress] opts out and adopts whatever the keystore holds (the postgres auto-generate
// first boot). Empty still errors, so "forgot to set it" is never read as deliberate auto-adoption.
func ValidateSignerIdentity(configured string, actual protocol.UnknownAddress, publicKey []byte) error {
	if configured == AutoSignerAddress {
		return nil
	}
	decoded, err := decodeSignerIdentity(configured)
	if err != nil {
		return err
	}
	if actual.Equal(decoded) || protocol.UnknownAddress(publicKey).Equal(decoded) {
		return nil
	}
	return signerIdentityMismatch(configured, actual)
}

// ResolveSignerIdentity returns the configured identity matching publicKey.
// EVM derivation occurs only when the configured length differs from the uncompressed public key.
func ResolveSignerIdentity(configured string, publicKey []byte) (protocol.UnknownAddress, error) {
	if configured == AutoSignerAddress {
		return publicKey, nil
	}
	decoded, err := decodeSignerIdentity(configured)
	if err != nil {
		return nil, err
	}
	if protocol.UnknownAddress(publicKey).Equal(decoded) {
		return publicKey, nil
	}
	if len(decoded) != len(publicKey) {
		address, err := EVMAddressFromPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		if address.Equal(decoded) {
			return address, nil
		}
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
		"signing address does not match signer_address: configured %s, keystore %s; "+
			"check signer_address and, for migration, ensure [key_import] imported the expected verifier signing key before first boot",
		configured, actual.String(),
	)
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
	r, s, err := protocol.SignV27RS(data, ecdsa.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	encodedSignature, err := protocol.EncodeSingleECDSASignatureRS(r, s)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, nil
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
	r32, s32, err := protocol.SignV27WithKeystoreSignerRS(data, s.keystoreSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	encodedSignature, err := protocol.EncodeSingleECDSASignatureRS(r32, s32)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, nil
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
