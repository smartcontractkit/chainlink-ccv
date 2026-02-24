package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"time"
)

// Constants for CCIP v1.7.
const (
	MessageIDSize                 = 32 // Size of a message ID in bytes
	MaxNumTokens                  = 1
	MaxDataSize                   = 1024 // 1kb
	MessageVersion                = 1    // Current message format version
	MinSizeRequiredMsgFields      = 27   // Minimum size for required fields in Message
	MinSizeRequiredMsgTokenFields = 34   // Minimum size for required fields in TokenTransfer
	MaxCCVsPerMessage             = 255  // Maximum number of CCV addresses per message (limited by uint8)
	MaxUnknownAddressBytes        = 255  // Maximum size of any UnknownAddress in bytes (limited by uint8)
)

var (
	vHash = Keccak256([]byte("CCIP1.7_MessageDiscovery_Version"))
	// MessageDiscoveryVersionLength is a 4 byte identifier.
	MessageDiscoveryVersionLength = 4
	// MessageDiscoveryVersion is the version used by the committee verifier to sign messages
	// that only need to be discovered, and not verified onchain.
	// 0x3c4605eb in hex.
	MessageDiscoveryVersion = vHash[:MessageDiscoveryVersionLength]
)

// TokenTransfer represents a chain-agnostic token transfer with canonical encoding.
type TokenTransfer struct {
	Amount                   *big.Int  `json:"amount"`
	SourcePoolAddress        ByteSlice `json:"source_pool_address"`
	SourceTokenAddress       ByteSlice `json:"source_token_address"`
	DestTokenAddress         ByteSlice `json:"dest_token_address"`
	TokenReceiver            ByteSlice `json:"token_receiver"`
	ExtraData                ByteSlice `json:"extra_data"`
	Version                  uint8     `json:"version"`
	SourcePoolAddressLength  uint8     `json:"source_pool_address_length"`
	SourceTokenAddressLength uint8     `json:"source_token_address_length"`
	DestTokenAddressLength   uint8     `json:"dest_token_address_length"`
	TokenReceiverLength      uint8     `json:"token_receiver_length"`
	ExtraDataLength          uint16    `json:"extra_data_length"`
}

// Encode returns the canonical encoding of this token transfer.
// Returns an error if any length field does not match the actual data length.
func (tt *TokenTransfer) Encode() ([]byte, error) {
	if err := tt.validateLengthFields(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	// Version (1 byte)
	_ = buf.WriteByte(tt.Version)

	amountBytes := make([]byte, 32)
	if tt.Amount != nil {
		if tt.Amount.Sign() < 0 {
			return nil, fmt.Errorf("amount cannot be negative")
		}
		if tt.Amount.BitLen() > 256 {
			return nil, fmt.Errorf("amount exceeds 256 bits: %d bits", tt.Amount.BitLen())
		}
		tt.Amount.FillBytes(amountBytes)
	}
	_, _ = buf.Write(amountBytes)

	// Source pool address
	_ = buf.WriteByte(tt.SourcePoolAddressLength)
	_, _ = buf.Write(tt.SourcePoolAddress)

	// Source token address
	_ = buf.WriteByte(tt.SourceTokenAddressLength)
	_, _ = buf.Write(tt.SourceTokenAddress)

	// Dest token address
	_ = buf.WriteByte(tt.DestTokenAddressLength)
	_, _ = buf.Write(tt.DestTokenAddress)

	// Token receiver
	_ = buf.WriteByte(tt.TokenReceiverLength)
	_, _ = buf.Write(tt.TokenReceiver)

	// Extra data (2 bytes length)
	if err := binary.Write(&buf, binary.BigEndian, tt.ExtraDataLength); err != nil {
		return nil, fmt.Errorf("failed to write extra data length: %w", err)
	}
	_, _ = buf.Write(tt.ExtraData)

	return buf.Bytes(), nil
}

// validateLengthFields checks that all length fields match their corresponding data slices.
func (tt *TokenTransfer) validateLengthFields() error {
	if int(tt.SourcePoolAddressLength) != len(tt.SourcePoolAddress) {
		return fmt.Errorf("SourcePoolAddressLength mismatch: field=%d, actual=%d", tt.SourcePoolAddressLength, len(tt.SourcePoolAddress))
	}
	if int(tt.SourceTokenAddressLength) != len(tt.SourceTokenAddress) {
		return fmt.Errorf("SourceTokenAddressLength mismatch: field=%d, actual=%d", tt.SourceTokenAddressLength, len(tt.SourceTokenAddress))
	}
	if int(tt.DestTokenAddressLength) != len(tt.DestTokenAddress) {
		return fmt.Errorf("DestTokenAddressLength mismatch: field=%d, actual=%d", tt.DestTokenAddressLength, len(tt.DestTokenAddress))
	}
	if int(tt.TokenReceiverLength) != len(tt.TokenReceiver) {
		return fmt.Errorf("TokenReceiverLength mismatch: field=%d, actual=%d", tt.TokenReceiverLength, len(tt.TokenReceiver))
	}
	if int(tt.ExtraDataLength) != len(tt.ExtraData) {
		return fmt.Errorf("ExtraDataLength mismatch: field=%d, actual=%d", tt.ExtraDataLength, len(tt.ExtraData))
	}
	return nil
}

// DecodeTokenTransfer decodes a TokenTransfer from bytes.
func DecodeTokenTransfer(data []byte) (*TokenTransfer, error) {
	if len(data) < MinSizeRequiredMsgTokenFields { // minimum size: version(1) + amount(32) + length(1)
		return nil, fmt.Errorf("data too short for token transfer")
	}

	reader := bytes.NewReader(data)
	tt := &TokenTransfer{}

	// Read version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	tt.Version = version

	// Read amount (32 bytes)
	amountBytes := make([]byte, 32)
	if _, err := io.ReadFull(reader, amountBytes); err != nil {
		return nil, fmt.Errorf("failed to read amount: %w", err)
	}
	tt.Amount = new(big.Int).SetBytes(amountBytes)

	// Read source pool address
	sourcePoolLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read source pool address length: %w", err)
	}
	tt.SourcePoolAddressLength = sourcePoolLen
	if sourcePoolLen == 0 {
		tt.SourcePoolAddress = nil
	} else {
		tt.SourcePoolAddress = make([]byte, sourcePoolLen)
		if _, err := io.ReadFull(reader, tt.SourcePoolAddress); err != nil {
			return nil, fmt.Errorf("failed to read source pool address: %w", err)
		}
	}

	// Read source token address
	sourceLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read source token address length: %w", err)
	}
	tt.SourceTokenAddressLength = sourceLen
	if sourceLen == 0 {
		tt.SourceTokenAddress = nil
	} else {
		tt.SourceTokenAddress = make([]byte, sourceLen)
		if _, err := io.ReadFull(reader, tt.SourceTokenAddress); err != nil {
			return nil, fmt.Errorf("failed to read source token address: %w", err)
		}
	}

	// Read dest token address
	destLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read dest token address length: %w", err)
	}
	tt.DestTokenAddressLength = destLen
	if destLen == 0 {
		tt.DestTokenAddress = nil
	} else {
		tt.DestTokenAddress = make([]byte, destLen)
		if _, err := io.ReadFull(reader, tt.DestTokenAddress); err != nil {
			return nil, fmt.Errorf("failed to read dest token address: %w", err)
		}
	}

	// Read token receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read token receiver length: %w", err)
	}
	tt.TokenReceiverLength = receiverLen
	if receiverLen == 0 {
		tt.TokenReceiver = nil
	} else {
		tt.TokenReceiver = make([]byte, receiverLen)
		if _, err := io.ReadFull(reader, tt.TokenReceiver); err != nil {
			return nil, fmt.Errorf("failed to read token receiver: %w", err)
		}
	}

	// Read extra data (2 bytes length)
	var extraLen uint16
	if err := binary.Read(reader, binary.BigEndian, &extraLen); err != nil {
		return nil, fmt.Errorf("failed to read extra data length: %w", err)
	}
	tt.ExtraDataLength = extraLen
	if extraLen == 0 {
		tt.ExtraData = nil
	} else {
		tt.ExtraData = make([]byte, extraLen)
		if _, err := io.ReadFull(reader, tt.ExtraData); err != nil {
			return nil, fmt.Errorf("failed to read extra data: %w", err)
		}
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return tt, nil
}

// Message represents the chain-agnostic CCIP message format.
type Message struct {
	Sender               UnknownAddress `json:"sender"`
	Data                 ByteSlice      `json:"data"`
	OnRampAddress        UnknownAddress `json:"on_ramp_address"`
	TokenTransfer        *TokenTransfer `json:"token_transfer"`
	OffRampAddress       UnknownAddress `json:"off_ramp_address"`
	DestBlob             ByteSlice      `json:"dest_blob"`
	Receiver             UnknownAddress `json:"receiver"`
	SourceChainSelector  ChainSelector  `json:"source_chain_selector"`
	DestChainSelector    ChainSelector  `json:"dest_chain_selector"`
	SequenceNumber       SequenceNumber `json:"sequence_number"`
	ExecutionGasLimit    uint32         `json:"execution_gas_limit"`
	CcipReceiveGasLimit  uint32         `json:"ccip_receive_gas_limit"`
	Finality             uint16         `json:"finality"`
	CcvAndExecutorHash   Bytes32        `json:"ccv_and_executor_hash"`
	DestBlobLength       uint16         `json:"dest_blob_length"`
	TokenTransferLength  uint16         `json:"token_transfer_length"`
	DataLength           uint16         `json:"data_length"`
	ReceiverLength       uint8          `json:"receiver_length"`
	SenderLength         uint8          `json:"sender_length"`
	Version              uint8          `json:"version"`
	OffRampAddressLength uint8          `json:"off_ramp_address_length"`
	OnRampAddressLength  uint8          `json:"on_ramp_address_length"`
}

// Encode returns the canonical encoding of this message.
// Matches Solidity MessageV1Codec._encodeMessageV1() format.
// Returns an error if any length field does not match the actual data length.
func (m *Message) Encode() ([]byte, error) {
	if err := m.validateLengthFields(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	// Version (1 byte)
	_ = buf.WriteByte(m.Version)

	// Chain selectors and sequence number (8 bytes each, big-endian)
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.SourceChainSelector)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.DestChainSelector)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, m.SequenceNumber); err != nil {
		return nil, err
	}

	// Gas limits (4 bytes each, big-endian)
	if err := binary.Write(&buf, binary.BigEndian, m.ExecutionGasLimit); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, m.CcipReceiveGasLimit); err != nil {
		return nil, err
	}

	// Finality (2 bytes, big-endian)
	if err := binary.Write(&buf, binary.BigEndian, m.Finality); err != nil {
		return nil, err
	}

	// CCV and executor hash (32 bytes)
	_, _ = buf.Write(m.CcvAndExecutorHash[:])

	// Variable length fields with length prefixes
	// On-ramp address
	_ = buf.WriteByte(m.OnRampAddressLength)
	_, _ = buf.Write(m.OnRampAddress)

	// Off-ramp address
	_ = buf.WriteByte(m.OffRampAddressLength)
	_, _ = buf.Write(m.OffRampAddress)

	// Sender
	_ = buf.WriteByte(m.SenderLength)
	_, _ = buf.Write(m.Sender)

	// Receiver
	_ = buf.WriteByte(m.ReceiverLength)
	_, _ = buf.Write(m.Receiver)

	// Dest blob
	if err := binary.Write(&buf, binary.BigEndian, m.DestBlobLength); err != nil {
		return nil, err
	}
	_, _ = buf.Write(m.DestBlob)

	// Token transfer
	var tokenTransferBytes []byte
	if m.TokenTransfer != nil {
		var err error
		tokenTransferBytes, err = m.TokenTransfer.Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode token transfer: %w", err)
		}
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(tokenTransferBytes))); err != nil { //nolint:gosec // G115: Length validated in NewMessage
		return nil, err
	}
	_, _ = buf.Write(tokenTransferBytes)

	// Data
	if err := binary.Write(&buf, binary.BigEndian, m.DataLength); err != nil {
		return nil, err
	}
	_, _ = buf.Write(m.Data)

	return buf.Bytes(), nil
}

// validateLengthFields checks that all length fields match their corresponding data slices.
func (m *Message) validateLengthFields() error {
	if int(m.OnRampAddressLength) != len(m.OnRampAddress) {
		return fmt.Errorf("OnRampAddressLength mismatch: field=%d, actual=%d", m.OnRampAddressLength, len(m.OnRampAddress))
	}
	if int(m.OffRampAddressLength) != len(m.OffRampAddress) {
		return fmt.Errorf("OffRampAddressLength mismatch: field=%d, actual=%d", m.OffRampAddressLength, len(m.OffRampAddress))
	}
	if int(m.SenderLength) != len(m.Sender) {
		return fmt.Errorf("SenderLength mismatch: field=%d, actual=%d", m.SenderLength, len(m.Sender))
	}
	if int(m.ReceiverLength) != len(m.Receiver) {
		return fmt.Errorf("ReceiverLength mismatch: field=%d, actual=%d", m.ReceiverLength, len(m.Receiver))
	}
	if int(m.DestBlobLength) != len(m.DestBlob) {
		return fmt.Errorf("DestBlobLength mismatch: field=%d, actual=%d", m.DestBlobLength, len(m.DestBlob))
	}
	if int(m.DataLength) != len(m.Data) {
		return fmt.Errorf("DataLength mismatch: field=%d, actual=%d", m.DataLength, len(m.Data))
	}
	return nil
}

// DecodeMessage decodes a Message from bytes.
// Matches Solidity MessageV1Codec._decodeMessageV1() format.
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < MinSizeRequiredMsgFields {
		return nil, fmt.Errorf("data too short for message")
	}

	reader := bytes.NewReader(data)
	msg := &Message{}

	// Read version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	msg.Version = version

	// Read chain selectors and sequence number
	var sourceChain, destChain, sequenceNumber uint64
	if err := binary.Read(reader, binary.BigEndian, &sourceChain); err != nil {
		return nil, fmt.Errorf("failed to read source chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &destChain); err != nil {
		return nil, fmt.Errorf("failed to read dest chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &sequenceNumber); err != nil {
		return nil, fmt.Errorf("failed to read sequence number: %w", err)
	}

	msg.SourceChainSelector = ChainSelector(sourceChain)
	msg.DestChainSelector = ChainSelector(destChain)
	msg.SequenceNumber = SequenceNumber(sequenceNumber)

	// Read gas limits
	if err := binary.Read(reader, binary.BigEndian, &msg.ExecutionGasLimit); err != nil {
		return nil, fmt.Errorf("failed to read execution gas limit: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &msg.CcipReceiveGasLimit); err != nil {
		return nil, fmt.Errorf("failed to read ccip receive gas limit: %w", err)
	}

	// Read finality
	if err := binary.Read(reader, binary.BigEndian, &msg.Finality); err != nil {
		return nil, fmt.Errorf("failed to read finality: %w", err)
	}

	// Read CCV and executor hash (32 bytes)
	if _, err := io.ReadFull(reader, msg.CcvAndExecutorHash[:]); err != nil {
		return nil, fmt.Errorf("failed to read ccv and executor hash: %w", err)
	}

	// Read on-ramp address
	onRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read on-ramp address length: %w", err)
	}
	msg.OnRampAddressLength = onRampLen
	if onRampLen == 0 {
		msg.OnRampAddress = nil
	} else {
		msg.OnRampAddress = make([]byte, onRampLen)
		if _, err := io.ReadFull(reader, msg.OnRampAddress); err != nil {
			return nil, fmt.Errorf("failed to read on-ramp address: %w", err)
		}
	}

	// Read off-ramp address
	offRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read off-ramp address length: %w", err)
	}
	msg.OffRampAddressLength = offRampLen
	if offRampLen == 0 {
		msg.OffRampAddress = nil
	} else {
		msg.OffRampAddress = make([]byte, offRampLen)
		if _, err := io.ReadFull(reader, msg.OffRampAddress); err != nil {
			return nil, fmt.Errorf("failed to read off-ramp address: %w", err)
		}
	}

	// Read sender
	senderLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read sender length: %w", err)
	}
	msg.SenderLength = senderLen
	if senderLen == 0 {
		msg.Sender = nil
	} else {
		msg.Sender = make([]byte, senderLen)
		if _, err := io.ReadFull(reader, msg.Sender); err != nil {
			return nil, fmt.Errorf("failed to read sender: %w", err)
		}
	}

	// Read receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read receiver length: %w", err)
	}
	msg.ReceiverLength = receiverLen
	if receiverLen == 0 {
		msg.Receiver = nil
	} else {
		msg.Receiver = make([]byte, receiverLen)
		if _, err := io.ReadFull(reader, msg.Receiver); err != nil {
			return nil, fmt.Errorf("failed to read receiver: %w", err)
		}
	}

	// Read dest blob
	var destBlobLen uint16
	if err := binary.Read(reader, binary.BigEndian, &destBlobLen); err != nil {
		return nil, fmt.Errorf("failed to read dest blob length: %w", err)
	}
	msg.DestBlobLength = destBlobLen
	if destBlobLen == 0 {
		msg.DestBlob = nil
	} else {
		msg.DestBlob = make([]byte, destBlobLen)
		if _, err := io.ReadFull(reader, msg.DestBlob); err != nil {
			return nil, fmt.Errorf("failed to read dest blob: %w", err)
		}
	}

	// Read token transfer
	var tokenTransferLen uint16
	if err := binary.Read(reader, binary.BigEndian, &tokenTransferLen); err != nil {
		return nil, fmt.Errorf("failed to read token transfer length: %w", err)
	}
	msg.TokenTransferLength = tokenTransferLen
	if tokenTransferLen == 0 {
		msg.TokenTransfer = nil
	} else {
		tokenTransferBytes := make([]byte, tokenTransferLen)
		if _, err := io.ReadFull(reader, tokenTransferBytes); err != nil {
			return nil, fmt.Errorf("failed to read token transfer: %w", err)
		}
		tt, err := DecodeTokenTransfer(tokenTransferBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode token transfer: %w", err)
		}
		msg.TokenTransfer = tt
	}

	// Read data
	var dataLen uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, fmt.Errorf("failed to read data length: %w", err)
	}
	msg.DataLength = dataLen
	if dataLen == 0 {
		msg.Data = nil
	} else {
		msg.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(reader, msg.Data); err != nil {
			return nil, fmt.Errorf("failed to read data: %w", err)
		}
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return msg, nil
}

// MessageID returns the message ID of this message (keccak256 of the canonical encoding).
func (m *Message) MessageID() (Bytes32, error) {
	encoded, err := m.Encode()
	if err != nil {
		return Bytes32{}, err
	}
	result := Keccak256(encoded)
	return result, nil
}

// MustMessageID returns the message ID of this message, returning empty Bytes32 on encoding errors.
// Use this when you want a simple getter that ignores errors (i.e. for logging).
func (m *Message) MustMessageID() Bytes32 {
	id, err := m.MessageID()
	if err != nil {
		return Bytes32{}
	}
	return id
}

// ReceiptWithBlob represents a chain-agnostic receipt with blob.
type ReceiptWithBlob struct {
	Issuer            UnknownAddress `json:"issuer"`
	Blob              ByteSlice      `json:"blob"`
	ExtraArgs         ByteSlice      `json:"extra_args"`
	DestGasLimit      uint64         `json:"dest_gas_limit"`
	DestBytesOverhead uint32         `json:"dest_bytes_overhead"`
	FeeTokenAmount    *big.Int       `json:"fee_token_amount"`
}

// CCV represents a Cross-Chain Verifier configuration.
type CCV struct {
	CCVAddress UnknownAddress
	Args       ByteSlice
	ArgsLen    uint16
}

// VerifierResult represents Cross-Chain Verification data (corresponds to VerifierResult proto).
type VerifierResult struct {
	MessageID              Bytes32          `json:"message_id"`
	Message                Message          `json:"message"`
	MessageCCVAddresses    []UnknownAddress `json:"message_ccv_addresses"`
	MessageExecutorAddress UnknownAddress   `json:"message_executor_address"`
	CCVData                ByteSlice        `json:"ccv_data"`
	Timestamp              time.Time        `json:"timestamp"`
	VerifierSourceAddress  UnknownAddress   `json:"verifier_source_address"`
	VerifierDestAddress    UnknownAddress   `json:"verifier_dest_address"`
}

// VerifierNodeResult represents node-level verification data (corresponds to CommitteeVerifierNodeResult proto).
type VerifierNodeResult struct {
	MessageID       Bytes32          `json:"message_id"`
	Message         Message          `json:"message"`
	CCVVersion      ByteSlice        `json:"ccv_version"`
	CCVAddresses    []UnknownAddress `json:"ccv_addresses"`
	ExecutorAddress UnknownAddress   `json:"executor_address"`
	Signature       ByteSlice        `json:"signature"`
}

// JobKey implements jobqueue.Jobable interface.
func (vr VerifierNodeResult) JobKey() (chainSelector uint64, messageID []byte) {
	return uint64(vr.Message.SourceChainSelector), vr.MessageID[:]
}

func (vr *VerifierResult) ValidateFieldsConsistent() error {
	err := vr.Message.ValidateCCVAndExecutorHash(vr.MessageCCVAddresses, vr.MessageExecutorAddress)
	if err != nil {
		return fmt.Errorf("failed to validate ccv and executor hash: %w", err)
	}

	checkedMessageID, err := vr.Message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to get message ID: %w", err)
	}
	if checkedMessageID != vr.MessageID {
		return fmt.Errorf("message ID mismatch: %s != %s", checkedMessageID.String(), vr.MessageID.String())
	}
	return nil
}

// QueryResponse represents the response from CCV data queries.
type QueryResponse struct {
	Timestamp *int64         `json:"timestamp,omitempty"`
	Data      VerifierResult `json:"data"`
}

// CCVNodeDataWriter defines the interface for verifiers to store CCV node data.
type CCVNodeDataWriter interface {
	// WriteCCVNodeData stores multiple CCV node data entries
	WriteCCVNodeData(ctx context.Context, ccvDataList []VerifierNodeResult) error
}

// OffchainStorageReader defines the interface for executors to query CCV data by timestamp.
type OffchainStorageReader interface {
	// ReadCCVData returns the next available CCV data entries.
	ReadCCVData(ctx context.Context) ([]QueryResponse, error)
}

// DiscoveryStorageReader define the interface to provide discovery services to off-chain components.
type DiscoveryStorageReader interface {
	OffchainStorageReader
	// GetSinceValue returns the latest sequence number used in the querying of the discovery service.
	GetSinceValue() int64
	// SetSinceValue allows moves the cursor of the reader within the discovery service
	// this happens automatically within the reader, this is an escape hatch mainly used to move the cursor backwards for replays.
	SetSinceValue(since int64)
}

// VerifierResultsAPI defines the interface for the public API to interact with verifiers
// It provides a singular API for offchain storage lookups by providing a batch endpoint
//
// Different transport layers (REST, S3) might not support batch lookups however this
// responsibility should be delegated to the underlying implementation.
type VerifierResultsAPI interface {
	// GetVerifications retrieves verifications for a set of provided messages.
	GetVerifications(ctx context.Context, messageIDs []Bytes32) (map[Bytes32]VerifierResult, error)
}

// Helper functions for creating empty/default values

// NewEmptyTokenTransfer creates an empty token transfer.
func NewEmptyTokenTransfer() *TokenTransfer {
	return &TokenTransfer{
		Version:                  MessageVersion,
		Amount:                   new(big.Int).SetBytes(make([]byte, 32)),
		SourcePoolAddressLength:  0,
		SourcePoolAddress:        nil,
		SourceTokenAddressLength: 0,
		SourceTokenAddress:       nil,
		DestTokenAddressLength:   0,
		DestTokenAddress:         nil,
		TokenReceiverLength:      0,
		TokenReceiver:            nil,
		ExtraDataLength:          0,
		ExtraData:                nil,
	}
}

// NewMessage creates a new message with the given parameters.
func NewMessage(
	sourceChain, destChain ChainSelector,
	sequenceNumber SequenceNumber,
	onRampAddress, offRampAddress UnknownAddress,
	finality uint16,
	executionGasLimit, ccipReceiveGasLimit uint32,
	ccvAndExecutorHash Bytes32,
	sender, receiver UnknownAddress,
	destBlob, data []byte,
	tokenTransfer *TokenTransfer,
) (*Message, error) {
	if len(onRampAddress) > math.MaxUint8 {
		return nil, fmt.Errorf("onRampAddress length exceeds maximum value")
	}
	if len(offRampAddress) > math.MaxUint8 {
		return nil, fmt.Errorf("offRampAddress length exceeds maximum value")
	}
	if len(sender) > math.MaxUint8 {
		return nil, fmt.Errorf("sender length exceeds maximum value")
	}
	if len(receiver) > math.MaxUint8 {
		return nil, fmt.Errorf("receiver length exceeds maximum value")
	}
	if len(data) > math.MaxUint16 {
		return nil, fmt.Errorf("data length exceeds maximum value")
	}
	if len(destBlob) > math.MaxUint16 {
		return nil, fmt.Errorf("destBlob length exceeds maximum value")
	}

	// Calculate token transfer length if present
	var tokenTransferLength uint16
	if tokenTransfer != nil {
		tokenTransferBytes, err := tokenTransfer.Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode token transfer: %w", err)
		}
		tokenTransferLength = uint16(len(tokenTransferBytes)) //nolint:gosec // G115: TokenTransfer.Encode() produces bounded output
	}

	//nolint:gosec // all verified
	return &Message{
		Version:              MessageVersion,
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		SequenceNumber:       sequenceNumber,
		ExecutionGasLimit:    executionGasLimit,
		CcipReceiveGasLimit:  ccipReceiveGasLimit,
		Finality:             finality,
		CcvAndExecutorHash:   ccvAndExecutorHash,
		OnRampAddressLength:  uint8(len(onRampAddress)),
		OnRampAddress:        onRampAddress.Bytes(),
		OffRampAddressLength: uint8(len(offRampAddress)),
		OffRampAddress:       offRampAddress.Bytes(),
		SenderLength:         uint8(len(sender)),
		Sender:               sender.Bytes(),
		ReceiverLength:       uint8(len(receiver)),
		Receiver:             receiver.Bytes(),
		DestBlobLength:       uint16(len(destBlob)),
		DestBlob:             destBlob,
		TokenTransfer:        tokenTransfer,
		TokenTransferLength:  tokenTransferLength,
		DataLength:           uint16(len(data)),
		Data:                 data,
	}, nil
}

// ComputeCCVAndExecutorHash calculates the keccak256 hash of CCV addresses and executor address.
// This matches the Solidity MessageV1Codec._computeCCVAndExecutorHash() function.
// Format: addressLength(1 byte) || ccv1 || ccv2 || ... || executor.
//
// The address length is derived dynamically from the executor address, allowing for
// chain-agnostic operation (e.g., 20 bytes for EVM, different lengths for other chains).
// All CCV addresses must have the same length as the executor address.
func ComputeCCVAndExecutorHash(ccvAddresses []UnknownAddress, executorAddress UnknownAddress) (Bytes32, error) {
	if len(ccvAddresses) > MaxCCVsPerMessage {
		return Bytes32{}, fmt.Errorf("too many CCV addresses: %d (max %d)", len(ccvAddresses), MaxCCVsPerMessage)
	}

	addressLength := len(executorAddress)
	if addressLength == 0 {
		return Bytes32{}, fmt.Errorf("executor address length cannot be 0")
	}

	for i, ccvAddr := range ccvAddresses {
		if len(ccvAddr) != addressLength {
			return Bytes32{}, fmt.Errorf("CCV address at index %d has different length: got %d, expected %d", i, len(ccvAddr), addressLength)
		}
	}

	// Calculate total length: 1 byte (address length) + N*addressLength bytes (CCVs) + addressLength bytes (executor)
	encodedLength := 1 + len(ccvAddresses)*addressLength + addressLength
	encoded := make([]byte, encodedLength)

	// First byte is the address length
	encoded[0] = byte(addressLength)

	// Copy CCV addresses
	offset := 1
	for _, ccvAddr := range ccvAddresses {
		copy(encoded[offset:offset+addressLength], ccvAddr.Bytes())
		offset += addressLength
	}

	// Copy executor address
	copy(encoded[offset:], executorAddress.Bytes())

	// Return keccak256 hash
	return Keccak256(encoded), nil
}

// ValidateCCVAndExecutorHash verifies that the ccvAndExecutorHash in the message matches
// the hash computed from the provided CCV addresses and executor address.
func (m *Message) ValidateCCVAndExecutorHash(ccvAddresses []UnknownAddress, executorAddress UnknownAddress) error {
	expectedHash, err := ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
	if err != nil {
		return fmt.Errorf("failed to compute ccvAndExecutorHash: %w", err)
	}

	if !bytes.Equal(m.CcvAndExecutorHash[:], expectedHash[:]) {
		return fmt.Errorf(
			"ccvAndExecutorHash mismatch: expected %s, got %s",
			expectedHash.String(),
			m.CcvAndExecutorHash.String(),
		)
	}

	return nil
}

// CCVAndExecutorHash validates that the message's ccvAndExecutorHash matches
// the hash computed from CCV addresses and executor address extracted from receipt blobs.
func ValidateCCVAndExecutorHash(message Message, receiptBlobs []ReceiptWithBlob) error {
	if len(receiptBlobs) == 0 {
		return fmt.Errorf("no receipt blobs to extract CCV and executor addresses from")
	}

	// Calculate number of token transfers and CCV receipts
	numTokenTransfers := 0
	if message.TokenTransferLength != 0 {
		numTokenTransfers = 1
	}
	numCCVBlobs := len(receiptBlobs) - numTokenTransfers - 2 // Executor + network fee

	if numCCVBlobs < 0 {
		return fmt.Errorf("invalid receipt structure: insufficient receipts (got %d, need at least %d for tokens + executor + network fee)",
			len(receiptBlobs), numTokenTransfers+2)
	}

	// Parse receipt structure
	receiptStructure, err := ParseReceiptStructure(
		receiptBlobs,
		numCCVBlobs,
		numTokenTransfers,
	)
	if err != nil {
		return fmt.Errorf("failed to parse receipt structure: %w", err)
	}

	return message.ValidateCCVAndExecutorHash(receiptStructure.CCVAddresses, receiptStructure.ExecutorAddress)
}
