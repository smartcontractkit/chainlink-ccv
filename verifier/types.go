package verifier

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
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
	ConfigDigest          [32]byte                                 `json:"config_digest"` // Configuration digest for this verifier
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

// MessageSigner defines the interface for signing messages
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature and verifier blob
	SignMessage(ctx context.Context, verificationTask common.VerificationTask, configDigest [32]byte) ([]byte, []byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() common.UnknownAddress
}

// ECDSASigner implements MessageSigner using ECDSA
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

// SignMessage signs a message event using ECDSA following the Python implementation logic
func (s *ECDSASigner) SignMessage(ctx context.Context, verificationTask common.VerificationTask, configDigest [32]byte) ([]byte, []byte, error) {
	// 1. Convert Any2Any to Any2EVM message
	any2evmMessage := ConvertAny2AnyToAny2EVM(&verificationTask.Message, 200000) // Default gas limit

	// 2. Create metadata for hash calculation
	metadata := &Any2EVMMessageMetadata{
		SourceChainSelector: any2evmMessage.Header.SourceChainSelector,
		DestChainSelector:   any2evmMessage.Header.DestChainSelector,
		OnRampAddress:       any2evmMessage.OnRampAddress,
	}

	// 3. Calculate message hash
	messageHash, err := CalculateMessageHash(any2evmMessage, metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate message hash: %w", err)
	}

	// 4. Extract nonce from receipt blobs
	var nonce uint64
	if len(verificationTask.ReceiptBlobs) > 0 && len(verificationTask.ReceiptBlobs[0]) > 0 {
		nonce, err = DecodeReceiptBlob(verificationTask.ReceiptBlobs[0])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode receipt blob: %w", err)
		}
	} else {
		// Use sequence number as fallback if no receipt blobs
		nonce = uint64(verificationTask.Message.Header.SequenceNumber)
	}

	// 5. Generate verifier blob
	verifierBlob, err := EncodeVerifierBlob(configDigest, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode verifier blob: %w", err)
	}

	// 6. Calculate signature hash
	signatureHash, err := CalculateSignatureHash(messageHash, verifierBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate signature hash: %w", err)
	}

	// 7. Sign the signature hash
	signature, err := crypto.Sign(signatureHash[:], s.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// 8. Extract r and s from signature and format as required by Python implementation
	rBytes := [32]byte{}
	sBytes := [32]byte{}
	copy(rBytes[:], signature[0:32])
	copy(sBytes[:], signature[32:64])

	// 9. Encode signature in the format expected by the system
	rs := [][32]byte{rBytes}
	ss := [][32]byte{sBytes}
	encodedSignature, err := EncodeSignatures(rs, ss)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return encodedSignature, verifierBlob, nil
}

// GetSignerAddress returns the address of the signer
func (s *ECDSASigner) GetSignerAddress() common.UnknownAddress {
	return s.address
}

// Utility functions for ABI encoding/decoding and hashing

// ABI types for encoding
var (
	bytes32Type, _      = abi.NewType("bytes32", "", nil)
	uint64Type, _       = abi.NewType("uint64", "", nil)
	uint256Type, _      = abi.NewType("uint256", "", nil)
	addressType, _      = abi.NewType("address", "", nil)
	bytesType, _        = abi.NewType("bytes", "", nil)
	bytes32ArrayType, _ = abi.NewType("bytes32[]", "", nil)
)

// EncodeVerifierBlob encodes config digest and nonce into verifier blob
// Equivalent to: abi.encode(["bytes32", "uint64"], [configDigest, nonce])
func EncodeVerifierBlob(configDigest [32]byte, nonce uint64) ([]byte, error) {
	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: uint64Type},
	}
	return args.Pack(configDigest, nonce)
}

// EncodeSignatures encodes r and s arrays into signature format
// Equivalent to: abi.encode(["bytes32[]", "bytes32[]], [rs, ss])
func EncodeSignatures(rs, ss [][32]byte) ([]byte, error) {
	args := abi.Arguments{
		{Type: bytes32ArrayType},
		{Type: bytes32ArrayType},
	}
	return args.Pack(rs, ss)
}

// DecodeReceiptBlob decodes nonce from receipt blob
// Equivalent to: abi.decode(receiptBlob, ["uint64"])
func DecodeReceiptBlob(receiptBlob []byte) (uint64, error) {
	if len(receiptBlob) < 32 {
		return 0, fmt.Errorf("receipt blob too short: %d bytes", len(receiptBlob))
	}

	args := abi.Arguments{
		{Type: uint64Type},
	}

	values, err := args.Unpack(receiptBlob)
	if err != nil {
		return 0, fmt.Errorf("failed to decode receipt blob: %w", err)
	}

	if len(values) == 0 {
		return 0, fmt.Errorf("no values decoded from receipt blob")
	}

	nonce, ok := values[0].(uint64)
	if !ok {
		return 0, fmt.Errorf("failed to cast decoded value to uint64")
	}

	return nonce, nil
}

// Keccak256 computes the Keccak256 hash of the input
func Keccak256(data []byte) [32]byte {
	hash := crypto.Keccak256(data)
	var result [32]byte
	copy(result[:], hash)
	return result
}

// CalculateSignatureHash calculates signature hash using Solidity-compatible method:
// keccak256(abi.encode(messageHash, keccak256(verifierBlob)))
func CalculateSignatureHash(messageHash [32]byte, verifierBlob []byte) ([32]byte, error) {
	verifierBlobHash := Keccak256(verifierBlob)

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: bytes32Type},
	}

	encoded, err := args.Pack([32]byte(messageHash), [32]byte(verifierBlobHash))
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to encode signature hash components: %w", err)
	}

	return Keccak256(encoded), nil
}

// Any2EVMMessageMetadata represents metadata for Any2EVM messages
type Any2EVMMessageMetadata struct {
	SourceChainSelector cciptypes.ChainSelector
	DestChainSelector   cciptypes.ChainSelector
	OnRampAddress       common.UnknownAddress
}

// Hash calculates the metadata hash
func (m *Any2EVMMessageMetadata) Hash() [32]byte {
	args := abi.Arguments{
		{Type: uint64Type}, // source chain selector
		{Type: uint64Type}, // dest chain selector
		{Type: bytesType},  // onramp address
	}

	encoded, err := args.Pack(
		uint64(m.SourceChainSelector),
		uint64(m.DestChainSelector),
		[]byte(m.OnRampAddress),
	)
	if err != nil {
		// This should not happen with valid input
		return [32]byte{}
	}

	return Keccak256(encoded)
}

// ConvertAny2AnyToAny2EVM converts Any2AnyVerifierMessage to Any2EVMVerifierMessage format
func ConvertAny2AnyToAny2EVM(any2any *common.Any2AnyVerifierMessage, gasLimit uint32) *common.Any2EVMVerifierMessage {
	if gasLimit == 0 {
		gasLimit = 200000 // Default gas limit
	}

	return &common.Any2EVMVerifierMessage{
		Header:        any2any.Header,
		Sender:        any2any.Sender,
		Data:          any2any.Data,
		Receiver:      any2any.Receiver,
		TokenTransfer: any2any.TokenTransfer,
		GasLimit:      gasLimit,
		ExtraArgs:     any2any.ExtraArgs,
		OnRampAddress: any2any.OnRampAddress,
	}
}

// CalculateMessageHash calculates the message hash following Solidity's Internal._hash logic
// This matches the EVM implementation in Internal.sol
func CalculateMessageHash(message *common.Any2EVMVerifierMessage, metadata *Any2EVMMessageMetadata) ([32]byte, error) {
	// Get domain separators from common package
	leafDomainSeparator := common.LeafDomainSeparator
	metadataHash := metadata.Hash()

	// Calculate nested hashes as per Solidity implementation
	// keccak256(abi.encode(sender, sequenceNumber, gasLimit))
	senderSeqGasArgs := abi.Arguments{
		{Type: bytesType},   // sender
		{Type: uint64Type},  // sequence number
		{Type: uint256Type}, // gas limit
	}

	senderSeqGasEncoded, err := senderSeqGasArgs.Pack(
		[]byte(message.Sender),
		uint64(message.Header.SequenceNumber),
		big.NewInt(int64(message.GasLimit)),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to encode sender/seq/gas: %w", err)
	}
	senderSeqGasHash := Keccak256(senderSeqGasEncoded)

	// keccak256(receiver) - convert to address format if needed
	receiverHash := Keccak256([]byte(message.Receiver))

	// keccak256(data)
	dataHash := Keccak256(message.Data)

	// keccak256(abi.encode(tokenTransfer))
	tokenTransferArgs := abi.Arguments{
		{Type: bytesType},   // source token address
		{Type: bytesType},   // dest token address
		{Type: bytesType},   // extra data
		{Type: uint256Type}, // amount
	}

	tokenTransferEncoded, err := tokenTransferArgs.Pack(
		[]byte(message.TokenTransfer.SourceTokenAddress),
		[]byte(message.TokenTransfer.DestTokenAddress),
		message.TokenTransfer.ExtraData,
		message.TokenTransfer.Amount,
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to encode token transfer: %w", err)
	}
	tokenTransferHash := Keccak256(tokenTransferEncoded)

	// Final hash: keccak256(abi.encode(leafDomainSeparator, metadataHash, senderSeqGasHash, receiverHash, dataHash, tokenTransferHash))
	finalArgs := abi.Arguments{
		{Type: bytes32Type}, // leaf domain separator
		{Type: bytes32Type}, // metadata hash
		{Type: bytes32Type}, // sender/seq/gas hash
		{Type: bytes32Type}, // receiver hash
		{Type: bytes32Type}, // data hash
		{Type: bytes32Type}, // token transfer hash
	}

	finalEncoded, err := finalArgs.Pack(
		[32]byte(leafDomainSeparator),
		[32]byte(metadataHash),
		[32]byte(senderSeqGasHash),
		[32]byte(receiverHash),
		[32]byte(dataHash),
		[32]byte(tokenTransferHash),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to encode final hash: %w", err)
	}

	return Keccak256(finalEncoded), nil
}

// ValidateMessage validates a verification task message
func ValidateMessage(verificationTask *common.VerificationTask, verifierOnRampAddress common.UnknownAddress) error {
	if verificationTask == nil {
		return fmt.Errorf("verification task is nil")
	}

	if len(verificationTask.Message.Header.MessageID) == 0 {
		return fmt.Errorf("message ID is empty")
	}

	// Check if the verifier onramp address is found as issuer in any verifier receipt
	// This matches the Python logic: any(receipt.issuer == self.verifier_onramp_address for receipt in event.message.verifier_receipts)
	found := false
	for _, receipt := range verificationTask.Message.VerifierReceipts {
		if receipt.Issuer.String() == verifierOnRampAddress.String() {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("verifier onramp address %s not found as issuer in any verifier receipt", verifierOnRampAddress.String())
	}

	return nil
}

// CreateCCVData creates CCVData from verification task, signature, and blob
func CreateCCVData(verificationTask *common.VerificationTask, signature []byte, verifierBlob []byte, sourceVerifierAddress common.UnknownAddress) *common.CCVData {
	return &common.CCVData{
		MessageID:             verificationTask.Message.Header.MessageID,
		SequenceNumber:        verificationTask.Message.Header.SequenceNumber,
		SourceChainSelector:   verificationTask.Message.Header.SourceChainSelector,
		DestChainSelector:     verificationTask.Message.Header.DestChainSelector,
		SourceVerifierAddress: sourceVerifierAddress,
		DestVerifierAddress:   common.UnknownAddress{}, // Will be set by the caller if needed
		CCVData:               signature,
		BlobData:              verifierBlob,
		Timestamp:             time.Now().UnixMicro(), // Unix timestamp in microseconds
		Message:               verificationTask.Message,
	}
}
