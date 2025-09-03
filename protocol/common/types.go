package common

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// Constants for CCIP v1.7
const (
	MaxNumTokens = 1
	MaxDataSize  = 1024 // 1kb
)

var (
	// Domain separators and message type hashes
	EVM2AnyMessageHash          = crypto.Keccak256([]byte("EVM_2_ANY_MESSAGE_HASH"))
	Any2EVMMessageHash          = crypto.Keccak256([]byte("ANY_2_EVM_MESSAGE_HASH"))
	LeafDomainSeparator         = make([]byte, 32)
	InternalNodeDomainSeparator = append(make([]byte, 31), byte(1))
)

// UnknownAddress represents an address on an unknown chain.
type UnknownAddress []byte

// NewUnknownAddressFromHex creates an UnknownAddress from a hex string
func NewUnknownAddressFromHex(s string) (UnknownAddress, error) {
	if s == "" {
		return UnknownAddress{}, nil
	}

	// Remove 0x prefix if present
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	return UnknownAddress(bytes), nil
}

// String returns the hex representation of the address
func (a UnknownAddress) String() string {
	if len(a) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(a)
}

// Bytes returns the raw bytes of the address
func (a UnknownAddress) Bytes() []byte {
	return []byte(a)
}

// MessageHeader represents the common header for all CCIP messages
type MessageHeader struct {
	MessageID           cciptypes.Bytes32       `json:"message_id"`
	SourceChainSelector cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector   cciptypes.ChainSelector `json:"dest_chain_selector"`
	SequenceNumber      cciptypes.SeqNum        `json:"sequence_number"`
}

// TokenTransfer represents a token transfer in the CCIP protocol
type TokenTransfer struct {
	SourceTokenAddress UnknownAddress `json:"source_token_address"`
	DestTokenAddress   UnknownAddress `json:"dest_token_address"`
	ExtraData          []byte         `json:"extra_data"`
	Amount             *big.Int       `json:"amount"`
}

// Receipt represents return data from a verifier or executor
type Receipt struct {
	Issuer            UnknownAddress `json:"issuer"`
	FeeTokenAmount    *big.Int       `json:"fee_token_amount"`
	DestGasLimit      uint64         `json:"dest_gas_limit"`
	DestBytesOverhead uint32         `json:"dest_bytes_overhead"`
	ExtraArgs         []byte         `json:"extra_args"`
}

// EVM2AnyVerifierMessage represents a message sent from an EVM chain
type EVM2AnyVerifierMessage struct {
	Header           MessageHeader  `json:"header"`
	Sender           UnknownAddress `json:"sender"`
	Data             []byte         `json:"data"`
	Receiver         UnknownAddress `json:"receiver"`
	FeeToken         UnknownAddress `json:"fee_token"`
	FeeTokenAmount   *big.Int       `json:"fee_token_amount"`
	FeeValueJuels    *big.Int       `json:"fee_value_juels"`
	TokenTransfer    TokenTransfer  `json:"token_transfer"`
	VerifierReceipts []Receipt      `json:"verifier_receipts"`
	ExecutorReceipt  *Receipt       `json:"executor_receipt"`
	TokenReceipt     *Receipt       `json:"token_receipt"`
	ExtraArgs        []byte         `json:"extra_args"`
}

// Any2AnyVerifierMessage represents a chain-agnostic CCIP message
type Any2AnyVerifierMessage struct {
	Header           MessageHeader  `json:"header"`
	Sender           UnknownAddress `json:"sender"`
	OnRampAddress    UnknownAddress `json:"onramp_address"` // CCVProxy address
	Data             []byte         `json:"data"`
	Receiver         UnknownAddress `json:"receiver"`
	FeeToken         UnknownAddress `json:"fee_token"`
	FeeTokenAmount   *big.Int       `json:"fee_token_amount"`
	FeeValueJuels    *big.Int       `json:"fee_value_juels"`
	TokenTransfer    TokenTransfer  `json:"token_transfer"`
	VerifierReceipts []Receipt      `json:"verifier_receipts"`
	ExecutorReceipt  *Receipt       `json:"executor_receipt"`
	TokenReceipt     *Receipt       `json:"token_receipt"`
	ExtraArgs        []byte         `json:"extra_args"`
}

// Any2EVMMessageMetadata represents metadata for Any2EVM messages
type Any2EVMMessageMetadata struct {
	SourceChainSelector cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector   cciptypes.ChainSelector `json:"dest_chain_selector"`
	OnRampAddress       UnknownAddress          `json:"onramp_address"`
}

// Any2EVMVerifierMessage represents a message to be executed on an EVM chain
type Any2EVMVerifierMessage struct {
	Header        MessageHeader  `json:"header"`
	Sender        UnknownAddress `json:"sender"`
	Data          []byte         `json:"data"`
	Receiver      UnknownAddress `json:"receiver"`
	TokenTransfer TokenTransfer  `json:"token_transfer"`
	GasLimit      uint32         `json:"gas_limit"`
	ExtraArgs     []byte         `json:"extra_args"`
	OnRampAddress UnknownAddress `json:"onramp_address"`
}

// VerificationTask represents the complete CCIPMessageSent event data from the onRamp/proxy
// This struct wraps the Any2AnyVerifierMessage with additional event fields that are important
// for verification and processing
type VerificationTask struct {
	Message      Any2AnyVerifierMessage `json:"message"`       // the complete message
	ReceiptBlobs [][]byte               `json:"receipt_blobs"` // receipt blobs from event
}

// CCVData represents Cross-Chain Verification data
type CCVData struct {
	MessageID             cciptypes.Bytes32       `json:"message_id"`
	SequenceNumber        cciptypes.SeqNum        `json:"sequence_number"`
	SourceChainSelector   cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector     cciptypes.ChainSelector `json:"dest_chain_selector"`
	SourceVerifierAddress UnknownAddress          `json:"source_verifier_address"`
	DestVerifierAddress   UnknownAddress          `json:"dest_verifier_address"`
	CCVData               []byte                  `json:"ccv_data"`  // The actual proof/signature
	BlobData              []byte                  `json:"blob_data"` // Additional verifier-specific data
	Timestamp             int64                   `json:"timestamp"` // Unix timestamp when verification completed (in microseconds)
	Message               Any2AnyVerifierMessage  `json:"message"`   // Complete message event being verified
}

// TimestampQueryResponse represents the response from timestamp-based CCV data queries.
// Contains the queried data organized by destination chain along with
// pagination metadata for efficient executor polling workflows.
type TimestampQueryResponse struct {
	// Data organized by destination chain selector
	Data map[cciptypes.ChainSelector][]CCVData `json:"data"`
	// Next timestamp to query (nil if no more data)
	NextTimestamp *int64 `json:"next_timestamp,omitempty"`
	// Whether more data exists at current timestamp
	HasMore bool `json:"has_more"`
	// Total number of items returned
	TotalCount int `json:"total_count"`
}

// OffchainStorageWriter defines the interface for verifiers to store CCV data.
// This interface is used by CCIP verifiers to store their CCV data
// after verification. Each verifier has write access to its own storage instance.
type OffchainStorageWriter interface {
	// StoreCCVData stores multiple CCV data entries in the offchain storage
	StoreCCVData(ctx context.Context, ccvDataList []CCVData) error
}

// OffchainStorageReader defines the interface for executors to query CCV data by timestamp.
// This interface is used by CCIP executors to poll for new CCV data using
// timestamp-based queries with offset pagination. Designed for efficient
// executor polling workflows.
type OffchainStorageReader interface {
	// GetCCVDataByTimestamp queries CCV data by timestamp with offset-based pagination
	GetCCVDataByTimestamp(
		ctx context.Context,
		destChainSelectors []cciptypes.ChainSelector,
		startTimestamp int64,
		sourceChainSelectors []cciptypes.ChainSelector,
		limit int,
		offset int,
	) (*TimestampQueryResponse, error)
}

// Cryptographic and Message Processing Utilities
// These utilities implement core CCIP v1.7 protocol logic for message verification

// ABI types for encoding - shared across the protocol
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

// Hash calculates the metadata hash for Any2EVMMessageMetadata
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
func ConvertAny2AnyToAny2EVM(any2any *Any2AnyVerifierMessage, gasLimit uint32) *Any2EVMVerifierMessage {
	if gasLimit == 0 {
		gasLimit = 200000 // Default gas limit
	}

	return &Any2EVMVerifierMessage{
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
func CalculateMessageHash(message *Any2EVMVerifierMessage, metadata *Any2EVMMessageMetadata) ([32]byte, error) {
	// Get domain separators from common package
	leafDomainSeparator := LeafDomainSeparator
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
func ValidateMessage(verificationTask *VerificationTask, verifierOnRampAddress UnknownAddress) error {
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
func CreateCCVData(verificationTask *VerificationTask, signature []byte, verifierBlob []byte, sourceVerifierAddress UnknownAddress) *CCVData {
	return &CCVData{
		MessageID:             verificationTask.Message.Header.MessageID,
		SequenceNumber:        verificationTask.Message.Header.SequenceNumber,
		SourceChainSelector:   verificationTask.Message.Header.SourceChainSelector,
		DestChainSelector:     verificationTask.Message.Header.DestChainSelector,
		SourceVerifierAddress: sourceVerifierAddress,
		DestVerifierAddress:   UnknownAddress{}, // Will be set by the caller if needed
		CCVData:               signature,
		BlobData:              verifierBlob,
		Timestamp:             time.Now().UnixMicro(), // Unix timestamp in microseconds
		Message:               verificationTask.Message,
	}
}
