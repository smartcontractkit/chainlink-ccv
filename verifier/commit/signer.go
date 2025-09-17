package commit

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg/signature"
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
func (s *ECDSASigner) SignMessage(ctx context.Context, verificationTask types.VerificationTask, sourceVerifierAddress types2.UnknownAddress) ([]byte, []byte, error) {
	message := verificationTask.Message

	// 1. Calculate message hash using the new chain-agnostic method
	messageHash, err := message.MessageID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute message ID: %w", err)
	}

	// 2. Find the verifier index that corresponds to our source verifier address
	verifierIndex, err := utils.FindVerifierIndexBySourceAddress(&verificationTask, sourceVerifierAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find verifier index: %w", err)
	}

	// 3. Extract nonce from the correct receipt blob using the verifier index
	var verifierBlob []byte
	if verifierIndex >= len(verificationTask.ReceiptBlobs) {
		return nil, nil, fmt.Errorf("no receipt blob found for verifier index: %d", verifierIndex)
	}
	verifierBlob = verificationTask.ReceiptBlobs[verifierIndex].Blob

	// 5. Calculate signature hash using the new method
	signatureHash, err := CalculateSignatureHash(messageHash, verifierBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate signature hash: %w", err)
	}

	// 6. Sign the signature hash with v=27 normalization
	r, sig_s, signerAddress, err := signature.SignV27(signatureHash[:], s.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// 7. Create signature data with signer address
	signatures := []signature.SignatureData{
		{
			R:      r,
			S:      sig_s,
			Signer: signerAddress,
		},
	}

	// 8. Encode signature using ABI encoding with ccvArgs (verifier blob)
	encodedSignature, err := signature.EncodeSignaturesABI(verifierBlob, signatures)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, verifierBlob, nil
}

// GetSignerAddress returns the address of the signer.
func (s *ECDSASigner) GetSignerAddress() types2.UnknownAddress {
	return s.address
}
