package verifier

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
)

// ECDSASigner implements MessageSigner using ECDSA with the new chain-agnostic message format
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	address    common.UnknownAddress
}

// NewECDSAMessageSigner creates a new ECDSA message signer
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
		address:    common.UnknownAddress(address.Bytes()),
	}, nil
}

// SignMessage signs a message event using ECDSA with the new chain-agnostic format
func (s *ECDSASigner) SignMessage(ctx context.Context, verificationTask common.VerificationTask, sourceVerifierAddress common.UnknownAddress) ([]byte, []byte, error) {
	message := &verificationTask.Message

	// 1. Calculate message hash using the new chain-agnostic method
	messageHash := message.MessageID()

	// 2. Find the verifier index that corresponds to our source verifier address
	verifierIndex, err := s.findVerifierIndexBySourceAddress(verificationTask, sourceVerifierAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find verifier index: %w", err)
	}

	// 3. Extract nonce from the correct receipt blob using the verifier index
	var verifierBlob []byte
	if verifierIndex < len(verificationTask.ReceiptBlobs) && len(verificationTask.ReceiptBlobs[verifierIndex].Blob) > 0 {
		verifierBlob = verificationTask.ReceiptBlobs[verifierIndex].Blob
	} else {
		return nil, nil, fmt.Errorf("receipt blob at index %d is empty", verifierIndex)
	}

	// 5. Calculate signature hash using the new method
	signatureHash, err := common.CalculateSignatureHash(messageHash, verifierBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate signature hash: %w", err)
	}

	// 6. Sign the signature hash
	signature, err := crypto.Sign(signatureHash[:], s.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// 7. Extract r and s from signature and format as required
	rBytes := [32]byte{}
	sBytes := [32]byte{}
	copy(rBytes[:], signature[0:32])
	copy(sBytes[:], signature[32:64])

	// 8. Encode signature in the format expected by the system
	rs := [][32]byte{rBytes}
	ss := [][32]byte{sBytes}
	encodedSignature, err := common.EncodeSignatures(rs, ss)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, verifierBlob, nil
}

// GetSignerAddress returns the address of the signer
func (s *ECDSASigner) GetSignerAddress() common.UnknownAddress {
	return s.address
}

// findVerifierIndexBySourceAddress finds the index of the source verifier address in the ReceiptBlobs array.
func (s *ECDSASigner) findVerifierIndexBySourceAddress(verificationTask common.VerificationTask, sourceVerifierAddress common.UnknownAddress) (int, error) {
	for i, receipt := range verificationTask.ReceiptBlobs {
		if receipt.Issuer.String() == sourceVerifierAddress.String() {
			return i, nil
		}
	}

	return -1, fmt.Errorf("source verifier address %s not found in ReceiptBlobs", sourceVerifierAddress.String())
}
