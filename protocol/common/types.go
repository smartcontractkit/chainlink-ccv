package common

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"

	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// Constants for CCIP v1.7
const (
	MaxNumTokens                  = 1
	MaxDataSize                   = 1024 // 1kb
	MessageVersion                = 1    // Current message format version
	MinSizeRequiredMsgFields      = 27   // Minimum size for required fields in Message
	MinSizeRequiredMsgTokenFields = 34   // Minimum size for required fields in TokenTransfer
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

// TokenTransfer represents a chain-agnostic token transfer with canonical encoding
type TokenTransfer struct {
	Version                  uint8    `json:"version"`
	Amount                   *big.Int `json:"amount"`
	SourceTokenAddressLength uint8    `json:"source_token_address_length"`
	SourceTokenAddress       []byte   `json:"source_token_address"`
	DestTokenAddressLength   uint8    `json:"dest_token_address_length"`
	DestTokenAddress         []byte   `json:"dest_token_address"`
	TokenReceiverLength      uint8    `json:"token_receiver_length"`
	TokenReceiver            []byte   `json:"token_receiver"`
	ExtraDataLength          uint8    `json:"extra_data_length"`
	ExtraData                []byte   `json:"extra_data"`
}

// Encode returns the canonical encoding of this token transfer
func (tt *TokenTransfer) Encode() []byte {
	var buf bytes.Buffer

	// Version (1 byte)
	_ = buf.WriteByte(tt.Version)

	// Amount (32 bytes, big-endian)
	amountBytes := make([]byte, 32)
	if tt.Amount != nil {
		tt.Amount.FillBytes(amountBytes)
	}
	_, _ = buf.Write(amountBytes)

	// Source token address
	_ = buf.WriteByte(tt.SourceTokenAddressLength)
	_, _ = buf.Write(tt.SourceTokenAddress)

	// Dest token address
	_ = buf.WriteByte(tt.DestTokenAddressLength)
	_, _ = buf.Write(tt.DestTokenAddress)

	// Token receiver
	_ = buf.WriteByte(tt.TokenReceiverLength)
	_, _ = buf.Write(tt.TokenReceiver)

	// Extra data
	_ = buf.WriteByte(tt.ExtraDataLength)
	_, _ = buf.Write(tt.ExtraData)

	return buf.Bytes()
}

// DecodeTokenTransfer decodes a TokenTransfer from bytes
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

	// Read source token address
	sourceLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read source token address length: %w", err)
	}
	tt.SourceTokenAddressLength = sourceLen
	tt.SourceTokenAddress = make([]byte, sourceLen)
	if _, err := io.ReadFull(reader, tt.SourceTokenAddress); err != nil {
		return nil, fmt.Errorf("failed to read source token address: %w", err)
	}

	// Read dest token address
	destLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read dest token address length: %w", err)
	}
	tt.DestTokenAddressLength = destLen
	tt.DestTokenAddress = make([]byte, destLen)
	if _, err := io.ReadFull(reader, tt.DestTokenAddress); err != nil {
		return nil, fmt.Errorf("failed to read dest token address: %w", err)
	}

	// Read token receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read token receiver length: %w", err)
	}
	tt.TokenReceiverLength = receiverLen
	tt.TokenReceiver = make([]byte, receiverLen)
	if _, err := io.ReadFull(reader, tt.TokenReceiver); err != nil {
		return nil, fmt.Errorf("failed to read token receiver: %w", err)
	}

	// Read extra data
	extraLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read extra data length: %w", err)
	}
	tt.ExtraDataLength = extraLen
	tt.ExtraData = make([]byte, extraLen)
	if _, err := io.ReadFull(reader, tt.ExtraData); err != nil {
		return nil, fmt.Errorf("failed to read extra data: %w", err)
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return tt, nil
}

// Message represents the chain-agnostic CCIP message format
type Message struct {
	// Protocol header
	Version              uint8                   `json:"version"`
	SourceChainSelector  cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector    cciptypes.ChainSelector `json:"dest_chain_selector"`
	SequenceNumber       cciptypes.SeqNum        `json:"sequence_number"`
	OnRampAddressLength  uint8                   `json:"on_ramp_address_length"`
	OnRampAddress        []byte                  `json:"on_ramp_address"`
	OffRampAddressLength uint8                   `json:"off_ramp_address_length"`
	OffRampAddress       []byte                  `json:"off_ramp_address"`

	// User provided data
	Finality            uint16 `json:"finality"`
	SenderLength        uint8  `json:"sender_length"`
	Sender              []byte `json:"sender"`
	ReceiverLength      uint8  `json:"receiver_length"`
	Receiver            []byte `json:"receiver"`
	DestBlobLength      uint16 `json:"dest_blob_length"`
	DestBlob            []byte `json:"dest_blob"`
	TokenTransferLength uint16 `json:"token_transfer_length"`
	TokenTransfer       []byte `json:"token_transfer"`
	DataLength          uint16 `json:"data_length"`
	Data                []byte `json:"data"`
}

// Encode returns the canonical encoding of this message
func (m *Message) Encode() ([]byte, error) {
	var buf bytes.Buffer

	// Protocol header
	_ = buf.WriteByte(m.Version)

	// Chain selectors and sequence number (8 bytes each, big-endian)
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.SourceChainSelector)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.DestChainSelector)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint64(m.SequenceNumber)); err != nil {
		return nil, err
	}

	// On-ramp address
	_ = buf.WriteByte(m.OnRampAddressLength)
	_, _ = buf.Write(m.OnRampAddress)

	// Off-ramp address
	_ = buf.WriteByte(m.OffRampAddressLength)
	_, _ = buf.Write(m.OffRampAddress)

	// User provided data
	if err := binary.Write(&buf, binary.BigEndian, m.Finality); err != nil {
		return nil, err
	}

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
	if err := binary.Write(&buf, binary.BigEndian, m.TokenTransferLength); err != nil {
		return nil, err
	}
	_, _ = buf.Write(m.TokenTransfer)

	// Data
	if err := binary.Write(&buf, binary.BigEndian, m.DataLength); err != nil {
		return nil, err
	}
	_, _ = buf.Write(m.Data)

	return buf.Bytes(), nil
}

// DecodeMessage decodes a Message from bytes
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
	var sourceChain, destChain, seqNum uint64
	if err := binary.Read(reader, binary.BigEndian, &sourceChain); err != nil {
		return nil, fmt.Errorf("failed to read source chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &destChain); err != nil {
		return nil, fmt.Errorf("failed to read dest chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &seqNum); err != nil {
		return nil, fmt.Errorf("failed to read sequence number: %w", err)
	}

	msg.SourceChainSelector = cciptypes.ChainSelector(sourceChain)
	msg.DestChainSelector = cciptypes.ChainSelector(destChain)
	msg.SequenceNumber = cciptypes.SeqNum(seqNum)

	// Read on-ramp address
	onRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read on-ramp address length: %w", err)
	}
	msg.OnRampAddressLength = onRampLen
	msg.OnRampAddress = make([]byte, onRampLen)
	if _, err := io.ReadFull(reader, msg.OnRampAddress); err != nil {
		return nil, fmt.Errorf("failed to read on-ramp address: %w", err)
	}

	// Read off-ramp address
	offRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read off-ramp address length: %w", err)
	}
	msg.OffRampAddressLength = offRampLen
	msg.OffRampAddress = make([]byte, offRampLen)
	if _, err := io.ReadFull(reader, msg.OffRampAddress); err != nil {
		return nil, fmt.Errorf("failed to read off-ramp address: %w", err)
	}

	// Read finality
	if err := binary.Read(reader, binary.BigEndian, &msg.Finality); err != nil {
		return nil, fmt.Errorf("failed to read finality: %w", err)
	}

	// Read sender
	senderLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read sender length: %w", err)
	}
	msg.SenderLength = senderLen
	msg.Sender = make([]byte, senderLen)
	if _, err := io.ReadFull(reader, msg.Sender); err != nil {
		return nil, fmt.Errorf("failed to read sender: %w", err)
	}

	// Read receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read receiver length: %w", err)
	}
	msg.ReceiverLength = receiverLen
	msg.Receiver = make([]byte, receiverLen)
	if _, err := io.ReadFull(reader, msg.Receiver); err != nil {
		return nil, fmt.Errorf("failed to read receiver: %w", err)
	}

	// Read dest blob
	var destBlobLen uint16
	if err := binary.Read(reader, binary.BigEndian, &destBlobLen); err != nil {
		return nil, fmt.Errorf("failed to read dest blob length: %w", err)
	}
	msg.DestBlobLength = destBlobLen
	msg.DestBlob = make([]byte, destBlobLen)
	if _, err := io.ReadFull(reader, msg.DestBlob); err != nil {
		return nil, fmt.Errorf("failed to read dest blob: %w", err)
	}

	// Read token transfer
	var tokenTransferLen uint16
	if err := binary.Read(reader, binary.BigEndian, &tokenTransferLen); err != nil {
		return nil, fmt.Errorf("failed to read token transfer length: %w", err)
	}
	msg.TokenTransferLength = tokenTransferLen
	msg.TokenTransfer = make([]byte, tokenTransferLen)
	if _, err := io.ReadFull(reader, msg.TokenTransfer); err != nil {
		return nil, fmt.Errorf("failed to read token transfer: %w", err)
	}

	// Read data
	var dataLen uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, fmt.Errorf("failed to read data length: %w", err)
	}
	msg.DataLength = dataLen
	msg.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(reader, msg.Data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return msg, nil
}

// MessageID returns the message ID of this message (keccak256 of the canonical encoding)
func (m *Message) MessageID() (cciptypes.Bytes32, error) {
	encoded, err := m.Encode()
	if err != nil {
		return cciptypes.Bytes32{}, err
	}
	hash := crypto.Keccak256(encoded)
	var result cciptypes.Bytes32
	copy(result[:], hash)
	return result, nil
}

// ReceiptWithBlob represents a chain-agnostic receipt with blob
type ReceiptWithBlob struct {
	Issuer            UnknownAddress `json:"issuer"`
	DestGasLimit      uint64         `json:"dest_gas_limit"`
	DestBytesOverhead uint32         `json:"dest_bytes_overhead"`
	Blob              []byte         `json:"blob"`
	ExtraArgs         []byte         `json:"extra_args"`
}

// CCVData represents Cross-Chain Verification data
type CCVData struct {
	MessageID             cciptypes.Bytes32       `json:"message_id"`
	SequenceNumber        cciptypes.SeqNum        `json:"sequence_number"`
	SourceChainSelector   cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector     cciptypes.ChainSelector `json:"dest_chain_selector"`
	SourceVerifierAddress UnknownAddress          `json:"source_verifier_address"`
	DestVerifierAddress   UnknownAddress          `json:"dest_verifier_address"`
	CCVData               []byte                  `json:"ccv_data"`      // The actual proof/signature
	BlobData              []byte                  `json:"blob_data"`     // Additional verifier-specific data
	Timestamp             int64                   `json:"timestamp"`     // Unix timestamp when verification completed (in microseconds)
	Message               Message                 `json:"message"`       // Complete message event being verified
	ReceiptBlobs          []ReceiptWithBlob       `json:"receipt_blobs"` // All receipt blobs for the message
}

// QueryResponse represents the response from CCV data queries.
type QueryResponse struct {
	// Data organized by destination chain selector
	Data CCVData `json:"data"`
	// Timestamp when the data was written (optional).
	Timestamp *int64 `json:"timestamp,omitempty"`
}

// OffchainStorageWriter defines the interface for verifiers to store CCV data.
type OffchainStorageWriter interface {
	// WriteCCVData stores multiple CCV data entries in the offchain storage
	WriteCCVData(ctx context.Context, ccvDataList []CCVData) error
}

// OffchainStorageReader defines the interface for executors to query CCV data by timestamp.
type OffchainStorageReader interface {
	// ReadCCVData returns the next available CCV data entries.
	ReadCCVData(ctx context.Context) ([]QueryResponse, error)
}

// Helper functions for creating empty/default values

// NewEmptyTokenTransfer creates an empty token transfer
func NewEmptyTokenTransfer() *TokenTransfer {
	return &TokenTransfer{
		Version:                  MessageVersion,
		Amount:                   big.NewInt(0),
		SourceTokenAddressLength: 0,
		SourceTokenAddress:       []byte{},
		DestTokenAddressLength:   0,
		DestTokenAddress:         []byte{},
		TokenReceiverLength:      0,
		TokenReceiver:            []byte{},
		ExtraDataLength:          0,
		ExtraData:                []byte{},
	}
}

// NewMessage creates a new message with the given parameters
func NewMessage(
	sourceChain, destChain cciptypes.ChainSelector,
	sequenceNumber cciptypes.SeqNum,
	onRampAddress, offRampAddress UnknownAddress,
	finality uint16,
	sender, receiver UnknownAddress,
	destBlob, data []byte,
	tokenTransfer *TokenTransfer,
) *Message {
	if tokenTransfer == nil {
		tokenTransfer = NewEmptyTokenTransfer()
	}

	tokenTransferBytes := tokenTransfer.Encode()

	return &Message{
		Version:             MessageVersion,
		SourceChainSelector: sourceChain,
		DestChainSelector:   destChain,
		SequenceNumber:      sequenceNumber,
		// #nosec G115 - ignore for now
		OnRampAddressLength: uint8(len(onRampAddress)),
		OnRampAddress:       onRampAddress.Bytes(),
		// #nosec G115 - ignore for now
		OffRampAddressLength: uint8(len(offRampAddress)),
		OffRampAddress:       offRampAddress.Bytes(),
		Finality:             finality,
		// #nosec G115 - ignore for now
		SenderLength: uint8(len(sender)),
		Sender:       sender.Bytes(),
		// #nosec G115 - ignore for now
		ReceiverLength: uint8(len(receiver)),
		Receiver:       receiver.Bytes(),
		// #nosec G115 - ignore for now
		DestBlobLength: uint16(len(destBlob)),
		DestBlob:       destBlob,
		// #nosec G115 - ignore for now
		TokenTransferLength: uint16(len(tokenTransferBytes)),
		TokenTransfer:       tokenTransferBytes,
		// #nosec G115 - ignore for now
		DataLength: uint16(len(data)),
		Data:       data,
	}
}
