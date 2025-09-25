package commit

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/signature"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/utils"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"

	types2 "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// ECDSASigner implements MessageSigner using ECDSA with the new chain-agnostic message format.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	address    types2.UnknownAddress
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
		address:    types2.UnknownAddress(address.Bytes()),
	}, nil
}

// SignMessage signs a message event using ECDSA with the new chain-agnostic format.
func (ecdsa *ECDSASigner) SignMessage(ctx context.Context, verificationTask types.VerificationTask, sourceVerifierAddress types2.UnknownAddress) ([]byte, error) {
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
	r, s, signerAddress, err := signature.SignV27(messageID[:], ecdsa.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// 4. Create signature data with signer address
	signatures := []signature.Data{
		{
			R:      r,
			S:      s,
			Signer: signerAddress,
		},
	}

	// 5. Encode signature using simple format
	encodedSignature, err := signature.EncodeSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, nil
}

// GetSignerAddress returns the address of the signer.
func (ecdsa *ECDSASigner) GetSignerAddress() types2.UnknownAddress {
	return ecdsa.address
}
