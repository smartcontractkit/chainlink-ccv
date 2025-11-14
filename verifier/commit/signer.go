package commit

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
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

	encodedSignature, err := protocol.EncodeSingleSignature(signature)
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

	encodedSignature, err := protocol.EncodeSingleSignature(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, nil
}
