package commit

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

// ECDSASigner implements MessageSigner using ECDSA with the new chain-agnostic message format.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
}

// NewECDSAMessageSignerFromString creates a new ECDSA message signer.
func NewECDSAMessageSignerFromString(privateKeyString string) (*ECDSASigner, protocol.UnknownAddress, error) {
	privateKey, err := ReadPrivateKeyFromString(privateKeyString)
	if err != nil {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("failed to read private key from environment variable: %w", err)
	}
	return NewECDSAMessageSigner(privateKey)
}

// NewECDSAMessageSigner creates a new ECDSA message signer.
func NewECDSAMessageSigner(privateKeyBytes []byte) (*ECDSASigner, protocol.UnknownAddress, error) {
	if len(privateKeyBytes) == 0 {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("private key cannot be empty")
	}

	// Convert bytes to ECDSA private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("failed to convert bytes to ECDSA private key: %w", err)
	}

	// Derive the address from the private key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("failed to cast public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	return &ECDSASigner{
		privateKey: privateKey,
	}, address[:], nil
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
func NewSignerFromKeystore(ctx context.Context, ks keystore.Keystore, keyName string) (verifier.MessageSigner, protocol.UnknownAddress, error) {
	// Get the key info to retrieve the public key
	keysResp, err := ks.GetKeys(ctx, keystore.GetKeysRequest{KeyNames: []string{keyName}})
	if err != nil {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("failed to get key from keystore: %w", err)
	}
	if len(keysResp.Keys) == 0 {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("key %q not found in keystore", keyName)
	}

	keyInfo := keysResp.Keys[0].KeyInfo
	if keyInfo.KeyType != keystore.ECDSA_S256 {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("key %q has unexpected type %s, expected %s", keyName, keyInfo.KeyType, keystore.ECDSA_S256)
	}

	// The public key from keystore is in SEC1 uncompressed format (65 bytes).
	// We need to derive the Ethereum address from it.
	if len(keyInfo.PublicKey) != 65 {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("unexpected public key length %d, expected 65", len(keyInfo.PublicKey))
	}

	// Convert SEC1 public key to Ethereum address
	pubKey, err := crypto.UnmarshalPubkey(keyInfo.PublicKey)
	if err != nil {
		return nil, protocol.UnknownAddress{}, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	address := crypto.PubkeyToAddress(*pubKey)

	// Create the adapter that bridges keystore.Signer to verifier.MessageSigner
	adapter := NewKeystoreSignerAdapter(ks, keyName)

	// Wrap with ECDSASignerWithKeystoreSigner to handle the protocol-specific signature encoding
	signer := NewECDSASignerWithKeystoreSigner(adapter)

	return signer, address[:], nil
}
