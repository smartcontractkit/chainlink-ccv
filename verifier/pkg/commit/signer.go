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

// ValidateSignerAddress checks that the key the verifier loaded is the one the job spec declares.
// Either side may describe the key as a 20-byte EVM address or as a SEC1 public key — EVM pins an
// address, Canton the 65-byte public key — and configured hex may omit the 0x prefix.
//
// [AutoSignerAddress] opts out and adopts whatever the keystore holds (the postgres auto-generate
// first boot). Empty still errors, so "forgot to set it" is never read as deliberate auto-adoption.
func ValidateSignerAddress(configured string, actual protocol.UnknownAddress) error {
	if configured == AutoSignerAddress {
		return nil
	}

	decoded, err := hex.DecodeString(strings.TrimPrefix(configured, "0x"))
	if err != nil {
		return fmt.Errorf("invalid signer_address %q: %w", configured, err)
	}
	if len(decoded) == 0 {
		return fmt.Errorf("invalid signer_address %q: empty address", configured)
	}

	if keysMatch(decoded, actual.Bytes()) {
		return nil
	}
	return fmt.Errorf(
		"signing key does not match signer_address: configured %s, keystore %s; "+
			"check signer_address and, for migration, ensure [key_import] imported the expected verifier signing key before first boot",
		configured, actual.String(),
	)
}

// keysMatch compares a configured key with the keystore's: identical bytes match outright, and
// otherwise both sides collapse to the EVM address derived from a public key, so a job pinning a
// public key matches a keystore reporting only its address, and vice versa.
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

// addressForKey returns the EVM address of an address or SEC1 public key (65-byte uncompressed or
// 33-byte compressed). Derivation is keccak-based, never truncation, so keys cannot match on shared
// trailing bytes.
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

	// Convert bytes to ECDSA private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("failed to convert bytes to ECDSA private key: %w", err)
	}

	// Derive the address from the private key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("failed to cast public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	return &ECDSASigner{
		privateKey: privateKey,
	}, crypto.FromECDSAPub(publicKeyECDSA), address[:], nil
}

// Sign signs some data with the new chain-agnostic format.
func (ecdsa *ECDSASigner) Sign(data []byte) ([]byte, error) {
	r, s, signerAddress, err := protocol.SignV27(data, ecdsa.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	signature := protocol.Data{
		R:      r,
		S:      s,
		Signer: signerAddress,
	}

	encodedSignature, err := protocol.EncodeSingleECDSASignature(signature)
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
	r32, s32, addr, err := protocol.SignV27WithKeystoreSigner(data, s.keystoreSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	signature := protocol.Data{
		R:      r32,
		S:      s32,
		Signer: addr,
	}

	encodedSignature, err := protocol.EncodeSingleECDSASignature(signature)
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

// NewSignerFromKeystore creates a message signer from a keystore.
// It loads the key from the keystore and returns a signer that implements verifier.MessageSigner,
// along with the public key (as UnknownAddress) for use in committee configuration.
func NewSignerFromKeystore(ctx context.Context, ks keystore.Keystore, keyName string) (signer verifier.MessageSigner, pubKey []byte, address protocol.UnknownAddress, err error) {
	// Get the key info to retrieve the public key
	//nolint:noeagerio // fail-fast by design: a verifier without its signing key can do no work, so the keystore read happens at startup rather than at first sign
	keysResp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	if err != nil {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("failed to get key from keystore: %w", err)
	}
	if len(keysResp.Keys) == 0 {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("key %q not found in keystore", keyName)
	}

	keyInfo := keysResp.Keys[0].KeyInfo
	if keyInfo.KeyType != keystore.ECDSA_S256 {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("key %q has unexpected type %s, expected %s", keyName, keyInfo.KeyType, keystore.ECDSA_S256)
	}

	// The public key from keystore is in SEC1 uncompressed format (65 bytes).
	// We need to derive the Ethereum address from it.
	if len(keyInfo.PublicKey) != 65 {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("unexpected public key length %d, expected 65", len(keyInfo.PublicKey))
	}

	// Convert SEC1 public key to Ethereum address
	ecdsaPublicKey, err := crypto.UnmarshalPubkey(keyInfo.PublicKey)
	if err != nil {
		return nil, nil, protocol.UnknownAddress{}, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	address = crypto.PubkeyToAddress(*ecdsaPublicKey).Bytes()

	return NewECDSASignerWithKeystoreSigner(NewKeystoreSignerAdapter(ks, keyName)), keyInfo.PublicKey, address[:], nil
}
