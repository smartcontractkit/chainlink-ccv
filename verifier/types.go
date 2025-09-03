package verifier

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// SourceReaderConfig contains configuration for the EVM source reader
type SourceReaderConfig struct {
	ChainSelector       cciptypes.ChainSelector `json:"chain_selector"`
	OnRampAddress       common.UnknownAddress   `json:"onramp_address"`
	PollInterval        time.Duration           `json:"poll_interval"`
	StartBlock          uint64                  `json:"start_block,omitempty"`
	MessagesChannelSize int                     `json:"messages_channel_size"`
}

// SourceConfig contains configuration for a single source chain
type SourceConfig struct {
	VerifierAddress common.UnknownAddress `json:"verifier_address"`
}

// CoordinatorConfig contains configuration for the verification coordinator
type CoordinatorConfig struct {
	VerifierID            string                                   `json:"verifier_id"`
	SourceConfigs         map[cciptypes.ChainSelector]SourceConfig `json:"source_configs"`
	ProcessingChannelSize int                                      `json:"processing_channel_size"`
	ProcessingTimeout     time.Duration                            `json:"processing_timeout"`
	MaxBatchSize          int                                      `json:"max_batch_size"`
}

// SourceReader defines the interface for reading CCIP messages from source chains
type SourceReader interface {
	// Start begins reading messages and pushing them to the messages channel
	Start(ctx context.Context) error

	// Stop stops the reader and closes the messages channel
	Stop() error

	// VerificationTaskChannel returns the channel where new message events are delivered
	VerificationTaskChannel() <-chan common.VerificationTask

	// HealthCheck returns the current health status of the reader
	HealthCheck(ctx context.Context) error
}

// MessageSigner defines the interface for signing messages using the new chain-agnostic format
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature and verifier blob
	SignMessage(ctx context.Context, verificationTask common.VerificationTask, sourceVerifierAddress common.UnknownAddress) ([]byte, []byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() common.UnknownAddress
}

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
	var nonce uint64
	if verifierIndex < len(verificationTask.ReceiptBlobs) && len(verificationTask.ReceiptBlobs[verifierIndex].Blob) > 0 {
		nonce, err = common.DecodeReceiptBlob(verificationTask.ReceiptBlobs[verifierIndex].Blob)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode receipt blob at index %d: %w", verifierIndex, err)
		}
	} else {
		nonce = uint64(0)
	}

	// 4. Generate verifier blob (simplified - just nonce now)
	verifierBlob, err := common.EncodeVerifierBlob(nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode verifier blob: %w", err)
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
