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
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/utils"
)

// ECDSASigner implements MessageSigner using ECDSA with the new chain-agnostic message format.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	address    protocol.UnknownAddress
}

// NewECDSAMessageSigner creates a new ECDSA message signer.
func NewECDSAMessageSigner(privateKeyBytes []byte) (*ECDSASigner, error) {
	if len(privateKeyBytes) == 0 {
		return nil, fmt.Errorf("private key cannot be empty")
	}

	// Convert bytes to ECDSA private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bytes to ECDSA private key: %w", err)
	}

	// Derive the address from the private key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	return &ECDSASigner{
		privateKey: privateKey,
		address:    protocol.UnknownAddress(address.Bytes()),
	}, nil
}

// SignMessage signs a message event using ECDSA with the new chain-agnostic format.
func (ecdsa *ECDSASigner) SignMessage(ctx context.Context, verificationTask verifier.VerificationTask, sourceVerifierAddress protocol.UnknownAddress) ([]byte, error) {
	message := verificationTask.Message

	messageID, err := message.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute message ID: %w", err)
	}

	_, err = utils.FindVerifierIndexBySourceAddress(&verificationTask, sourceVerifierAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find verifier index: %w", err)
	}

	// 3. Sign the signature hash with v=27 normalization
	r, s, signerAddress, err := protocol.SignV27(messageID[:], ecdsa.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// 4. Create signature data with signer address
	signatures := []protocol.Data{
		{
			R:      r,
			S:      s,
			Signer: signerAddress,
		},
	}

	// 5. Encode signature using simple format
	encodedSignature, err := protocol.EncodeSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, nil
}

// GetSignerAddress returns the address of the signer.
func (ecdsa *ECDSASigner) GetSignerAddress() protocol.UnknownAddress {
	return ecdsa.address
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
